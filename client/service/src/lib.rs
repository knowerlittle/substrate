// Copyright 2017-2020 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

//! Substrate service. Starts a thread that spins up the network, client, and extrinsic pool.
//! Manages communication between them.

#![warn(missing_docs)]

pub mod config;
#[macro_use]
pub mod chain_ops;
pub mod error;

mod builder;
mod status_sinks;

use std::{borrow::Cow, io, pin::Pin};
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::task::{Poll, Context};
use parking_lot::Mutex;

use sc_client::Client;
use exit_future::Signal;
use futures::{
	Future, FutureExt, Stream, StreamExt,
	future::select, channel::mpsc,
	compat::*,
	sink::SinkExt,
	task::{Spawn, FutureObj, SpawnError},
};
use sc_network::{
	NetworkService, NetworkState, specialization::NetworkSpecialization,
	PeerId, ReportHandle,
};
use log::{log, warn, debug, error, Level};
use codec::{Encode, Decode};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{NumberFor, Block as BlockT};

pub use self::error::Error;
pub use self::builder::{
	new_full_client,
	ServiceBuilder, ServiceBuilderCommand, TFullClient, TLightClient, TFullBackend, TLightBackend,
	TFullCallExecutor, TLightCallExecutor,
};
pub use config::{Configuration, Roles, PruningMode};
pub use sc_chain_spec::{ChainSpec, Properties, RuntimeGenesis, Extension as ChainSpecExtension};
pub use sp_transaction_pool::{TransactionPool, InPoolTransaction, error::IntoPoolError};
pub use sc_transaction_pool::txpool::Options as TransactionPoolOptions;
pub use sc_client::FinalityNotifications;
pub use sc_rpc::Metadata as RpcMetadata;
#[doc(hidden)]
pub use std::{ops::Deref, result::Result, sync::Arc};
#[doc(hidden)]
pub use sc_network::{FinalityProofProvider, OnDemand, config::BoxFinalityProofRequestBuilder};

const DEFAULT_PROTOCOL_ID: &str = "sup";

/// Substrate service.
pub struct Service<TBl, TCl, TSc, TNetStatus, TNet, TTxPool, TOc> {
	client: Arc<TCl>,
	select_chain: Option<TSc>,
	network: Arc<TNet>,
	/// Sinks to propagate network status updates.
	/// For each element, every time the `Interval` fires we push an element on the sender.
	network_status_sinks: Arc<Mutex<status_sinks::StatusSinks<(TNetStatus, NetworkState)>>>,
	transaction_pool: Arc<TTxPool>,
	/// A future that resolves when the service has exited, this is useful to
	/// make sure any internally spawned futures stop when the service does.
	exit: exit_future::Exit,
	/// A signal that makes the exit future above resolve, fired on service drop.
	signal: Option<Signal>,
	/// Send a signal when a spawned essential task has concluded. The next time
	/// the service future is polled it should complete with an error.
	essential_failed_tx: mpsc::UnboundedSender<()>,
	/// A receiver for spawned essential-tasks concluding.
	essential_failed_rx: mpsc::UnboundedReceiver<()>,
	/// Sender for futures that must be spawned as background tasks.
	to_spawn_tx: mpsc::UnboundedSender<(Pin<Box<dyn Future<Output = ()> + Send>>, Cow<'static, str>)>,
	/// Receiver for futures that must be spawned as background tasks.
	to_spawn_rx: mpsc::UnboundedReceiver<(Pin<Box<dyn Future<Output = ()> + Send>>, Cow<'static, str>)>,
	/// How to spawn background tasks.
	task_executor: Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,
	rpc_handlers: sc_rpc_server::RpcHandler<sc_rpc::Metadata>,
	_rpc: Box<dyn std::any::Any + Send + Sync>,
	_telemetry: Option<sc_telemetry::Telemetry>,
	_telemetry_on_connect_sinks: Arc<Mutex<Vec<futures::channel::mpsc::UnboundedSender<()>>>>,
	_offchain_workers: Option<Arc<TOc>>,
	keystore: sc_keystore::KeyStorePtr,
	marker: PhantomData<TBl>,
}

/// Alias for a an implementation of `futures::future::Executor`.
pub type TaskExecutor = Arc<dyn Spawn + Send + Sync>;

/// An handle for spawning tasks in the service.
#[derive(Clone)]
pub struct SpawnTaskHandle {
	sender: mpsc::UnboundedSender<(Pin<Box<dyn Future<Output = ()> + Send>>, Cow<'static, str>)>,
	on_exit: exit_future::Exit,
}

impl SpawnTaskHandle {
	/// Spawns the given task with the given name.
	pub fn spawn(&self, name: impl Into<Cow<'static, str>>, task: impl Future<Output = ()> + Send + 'static) {
		let on_exit = self.on_exit.clone();
		let future = async move {
			futures::pin_mut!(task);
			let _ = select(on_exit, task).await;
		};
		if self.sender.unbounded_send((Box::pin(future), name.into())).is_err() {
			error!("Failed to send task to spawn over channel");
		}
	}
}

impl Spawn for SpawnTaskHandle {
	fn spawn_obj(&self, future: FutureObj<'static, ()>)
	-> Result<(), SpawnError> {
		let future = select(self.on_exit.clone(), future).map(drop);
		self.sender.unbounded_send((Box::pin(future), From::from("unnamed")))
			.map_err(|_| SpawnError::shutdown())
	}
}

type Boxed01Future01 = Box<dyn futures01::Future<Item = (), Error = ()> + Send + 'static>;

impl futures01::future::Executor<Boxed01Future01> for SpawnTaskHandle {
	fn execute(&self, future: Boxed01Future01) -> Result<(), futures01::future::ExecuteError<Boxed01Future01>>{
		self.spawn("unnamed", future.compat().map(drop));
		Ok(())
	}
}

/// Abstraction over a Substrate service.
pub trait AbstractService: 'static + Future<Output = Result<(), Error>> +
	Spawn + Send + Unpin {
	/// Type of block of this chain.
	type Block: BlockT;
	/// Backend storage for the client.
	type Backend: 'static + sc_client_api::backend::Backend<Self::Block>;
	/// How to execute calls towards the runtime.
	type CallExecutor: 'static + sc_client::CallExecutor<Self::Block> + Send + Sync + Clone;
	/// API that the runtime provides.
	type RuntimeApi: Send + Sync;
	/// Chain selection algorithm.
	type SelectChain: sp_consensus::SelectChain<Self::Block>;
	/// Transaction pool.
	type TransactionPool: TransactionPool<Block = Self::Block>;
	/// Network specialization.
	type NetworkSpecialization: NetworkSpecialization<Self::Block>;

	/// Get event stream for telemetry connection established events.
	fn telemetry_on_connect_stream(&self) -> futures::channel::mpsc::UnboundedReceiver<()>;

	/// return a shared instance of Telemetry (if enabled)
	fn telemetry(&self) -> Option<sc_telemetry::Telemetry>;

	/// Spawns a task in the background that runs the future passed as parameter.
	fn spawn_task(&self, name: impl Into<Cow<'static, str>>, task: impl Future<Output = ()> + Send + 'static);

	/// Spawns a task in the background that runs the future passed as
	/// parameter. The given task is considered essential, i.e. if it errors we
	/// trigger a service exit.
	fn spawn_essential_task(&self, name: impl Into<Cow<'static, str>>, task: impl Future<Output = ()> + Send + 'static);

	/// Returns a handle for spawning tasks.
	fn spawn_task_handle(&self) -> SpawnTaskHandle;

	/// Returns the keystore that stores keys.
	fn keystore(&self) -> sc_keystore::KeyStorePtr;

	/// Starts an RPC query.
	///
	/// The query is passed as a string and must be a JSON text similar to what an HTTP client
	/// would for example send.
	///
	/// Returns a `Future` that contains the optional response.
	///
	/// If the request subscribes you to events, the `Sender` in the `RpcSession` object is used to
	/// send back spontaneous events.
	fn rpc_query(&self, mem: &RpcSession, request: &str) -> Pin<Box<dyn Future<Output = Option<String>> + Send>>;

	/// Get shared client instance.
	fn client(&self) -> Arc<sc_client::Client<Self::Backend, Self::CallExecutor, Self::Block, Self::RuntimeApi>>;

	/// Get clone of select chain.
	fn select_chain(&self) -> Option<Self::SelectChain>;

	/// Get shared network instance.
	fn network(&self)
		-> Arc<NetworkService<Self::Block, Self::NetworkSpecialization, <Self::Block as BlockT>::Hash>>;

	/// Returns a receiver that periodically receives a status of the network.
	fn network_status(&self, interval: Duration) -> mpsc::UnboundedReceiver<(NetworkStatus<Self::Block>, NetworkState)>;

	/// Get shared transaction pool instance.
	fn transaction_pool(&self) -> Arc<Self::TransactionPool>;

	/// Get a handle to a future that will resolve on exit.
	fn on_exit(&self) -> ::exit_future::Exit;
}

impl<TBl, TBackend, TExec, TRtApi, TSc, TNetSpec, TExPool, TOc> AbstractService for
	Service<TBl, Client<TBackend, TExec, TBl, TRtApi>, TSc, NetworkStatus<TBl>,
		NetworkService<TBl, TNetSpec, TBl::Hash>, TExPool, TOc>
where
	TBl: BlockT + Unpin,
	TBackend: 'static + sc_client_api::backend::Backend<TBl>,
	TExec: 'static + sc_client::CallExecutor<TBl> + Send + Sync + Clone,
	TRtApi: 'static + Send + Sync,
	TSc: sp_consensus::SelectChain<TBl> + 'static + Clone + Send + Unpin,
	TExPool: 'static + TransactionPool<Block = TBl>,
	TOc: 'static + Send + Sync,
	TNetSpec: NetworkSpecialization<TBl>,
{
	type Block = TBl;
	type Backend = TBackend;
	type CallExecutor = TExec;
	type RuntimeApi = TRtApi;
	type SelectChain = TSc;
	type TransactionPool = TExPool;
	type NetworkSpecialization = TNetSpec;

	fn telemetry_on_connect_stream(&self) -> futures::channel::mpsc::UnboundedReceiver<()> {
		let (sink, stream) = futures::channel::mpsc::unbounded();
		self._telemetry_on_connect_sinks.lock().push(sink);
		stream
	}

	fn telemetry(&self) -> Option<sc_telemetry::Telemetry> {
		self._telemetry.as_ref().map(|t| t.clone())
	}

	fn keystore(&self) -> sc_keystore::KeyStorePtr {
		self.keystore.clone()
	}

	fn spawn_task(&self, name: impl Into<Cow<'static, str>>, task: impl Future<Output = ()> + Send + 'static) {
		let on_exit = self.on_exit();
		let task = async move {
			futures::pin_mut!(task);
			let _ = select(on_exit, task).await;
		};
		let _ = self.to_spawn_tx.unbounded_send((Box::pin(task), name.into()));
	}

	fn spawn_essential_task(&self, name: impl Into<Cow<'static, str>>, task: impl Future<Output = ()> + Send + 'static) {
		let mut essential_failed = self.essential_failed_tx.clone();
		let essential_task = std::panic::AssertUnwindSafe(task)
			.catch_unwind()
			.map(move |_| {
				error!("Essential task failed. Shutting down service.");
				let _ = essential_failed.send(());
			});
		let on_exit = self.on_exit();
		let task = async move {
			futures::pin_mut!(essential_task);
			let _ = select(on_exit, essential_task).await;
		};

		let _ = self.to_spawn_tx.unbounded_send((Box::pin(task), name.into()));
	}

	fn spawn_task_handle(&self) -> SpawnTaskHandle {
		SpawnTaskHandle {
			sender: self.to_spawn_tx.clone(),
			on_exit: self.on_exit(),
		}
	}

	fn rpc_query(&self, mem: &RpcSession, request: &str) -> Pin<Box<dyn Future<Output = Option<String>> + Send>> {
		Box::pin(
			self.rpc_handlers.handle_request(request, mem.metadata.clone())
				.compat()
				.map(|res| res.expect("this should never fail"))
		)
	}

	fn client(&self) -> Arc<sc_client::Client<Self::Backend, Self::CallExecutor, Self::Block, Self::RuntimeApi>> {
		self.client.clone()
	}

	fn select_chain(&self) -> Option<Self::SelectChain> {
		self.select_chain.clone()
	}

	fn network(&self)
		-> Arc<NetworkService<Self::Block, Self::NetworkSpecialization, <Self::Block as BlockT>::Hash>>
	{
		self.network.clone()
	}

	fn network_status(&self, interval: Duration) -> mpsc::UnboundedReceiver<(NetworkStatus<Self::Block>, NetworkState)> {
		let (sink, stream) = mpsc::unbounded();
		self.network_status_sinks.lock().push(interval, sink);
		stream
	}

	fn transaction_pool(&self) -> Arc<Self::TransactionPool> {
		self.transaction_pool.clone()
	}

	fn on_exit(&self) -> exit_future::Exit {
		self.exit.clone()
	}
}

impl<TBl: Unpin, TCl, TSc: Unpin, TNetStatus, TNet, TTxPool, TOc> Future for
	Service<TBl, TCl, TSc, TNetStatus, TNet, TTxPool, TOc>
{
	type Output = Result<(), Error>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
		let this = Pin::into_inner(self);

		match Pin::new(&mut this.essential_failed_rx).poll_next(cx) {
			Poll::Pending => {},
			Poll::Ready(_) => {
				// Ready(None) should not be possible since we hold a live
				// sender.
				return Poll::Ready(Err(Error::Other("Essential task failed.".into())));
			}
		}

		while let Poll::Ready(Some((task_to_spawn, name))) = Pin::new(&mut this.to_spawn_rx).poll_next(cx) {
			(this.task_executor)(Box::pin(futures_diagnose::diagnose(name, task_to_spawn)));
		}

		// The service future never ends.
		Poll::Pending
	}
}

impl<TBl, TCl, TSc, TNetStatus, TNet, TTxPool, TOc> Spawn for
	Service<TBl, TCl, TSc, TNetStatus, TNet, TTxPool, TOc>
{
	fn spawn_obj(
		&self,
		future: FutureObj<'static, ()>
	) -> Result<(), SpawnError> {
		self.to_spawn_tx.unbounded_send((Box::pin(future), From::from("unnamed")))
			.map_err(|_| SpawnError::shutdown())
	}
}

/// Builds a never-ending future that continuously polls the network.
///
/// The `status_sink` contain a list of senders to send a periodic network status to.
fn build_network_future<
	B: BlockT,
	C: sc_client::BlockchainEvents<B>,
	S: sc_network::specialization::NetworkSpecialization<B>,
	H: sc_network::ExHashT
> (
	roles: Roles,
	mut network: sc_network::NetworkWorker<B, S, H>,
	client: Arc<C>,
	status_sinks: Arc<Mutex<status_sinks::StatusSinks<(NetworkStatus<B>, NetworkState)>>>,
	mut rpc_rx: mpsc::UnboundedReceiver<sc_rpc::system::Request<B>>,
	should_have_peers: bool,
) -> impl Future<Output = ()> {
	let mut imported_blocks_stream = client.import_notification_stream().fuse();
	let mut finality_notification_stream = client.finality_notification_stream().fuse();

	futures::future::poll_fn(move |cx| {
		let before_polling = Instant::now();

		// We poll `imported_blocks_stream`.
		while let Poll::Ready(Some(notification)) = Pin::new(&mut imported_blocks_stream).poll_next(cx) {
			network.on_block_imported(notification.hash, notification.header, Vec::new(), notification.is_new_best);
		}

		// We poll `finality_notification_stream`, but we only take the last event.
		let mut last = None;
		while let Poll::Ready(Some(item)) = Pin::new(&mut finality_notification_stream).poll_next(cx) {
			last = Some(item);
		}
		if let Some(notification) = last {
			network.on_block_finalized(notification.hash, notification.header);
		}

		// Poll the RPC requests and answer them.
		while let Poll::Ready(Some(request)) = Pin::new(&mut rpc_rx).poll_next(cx) {
			match request {
				sc_rpc::system::Request::Health(sender) => {
					let _ = sender.send(sc_rpc::system::Health {
						peers: network.peers_debug_info().len(),
						is_syncing: network.service().is_major_syncing(),
						should_have_peers,
					});
				},
				sc_rpc::system::Request::Peers(sender) => {
					let _ = sender.send(network.peers_debug_info().into_iter().map(|(peer_id, p)|
						sc_rpc::system::PeerInfo {
							peer_id: peer_id.to_base58(),
							roles: format!("{:?}", p.roles),
							protocol_version: p.protocol_version,
							best_hash: p.best_hash,
							best_number: p.best_number,
						}
					).collect());
				}
				sc_rpc::system::Request::NetworkState(sender) => {
					if let Some(network_state) = serde_json::to_value(&network.network_state()).ok() {
						let _ = sender.send(network_state);
					}
				}
				sc_rpc::system::Request::NetworkAddReservedPeer(peer_addr, sender) => {
					let x = network.add_reserved_peer(peer_addr)
						.map_err(sc_rpc::system::error::Error::MalformattedPeerArg);
					let _ = sender.send(x);
				}
				sc_rpc::system::Request::NetworkRemoveReservedPeer(peer_id, sender) => {
					let _ = match peer_id.parse::<PeerId>() {
						Ok(peer_id) => {
							network.remove_reserved_peer(peer_id);
							sender.send(Ok(()))
						}
						Err(e) => sender.send(Err(sc_rpc::system::error::Error::MalformattedPeerArg(
							e.to_string(),
						))),
					};
				}
				sc_rpc::system::Request::NodeRoles(sender) => {
					use sc_rpc::system::NodeRole;

					let node_roles = (0 .. 8)
						.filter(|&bit_number| (roles.bits() >> bit_number) & 1 == 1)
						.map(|bit_number| match Roles::from_bits(1 << bit_number) {
							Some(Roles::AUTHORITY) => NodeRole::Authority,
							Some(Roles::LIGHT) => NodeRole::LightClient,
							Some(Roles::FULL) => NodeRole::Full,
							_ => NodeRole::UnknownRole(bit_number),
						})
						.collect();

					let _ = sender.send(node_roles);
				}
			};
		}

		// Interval report for the external API.
		status_sinks.lock().poll(cx, || {
			let status = NetworkStatus {
				sync_state: network.sync_state(),
				best_seen_block: network.best_seen_block(),
				num_sync_peers: network.num_sync_peers(),
				num_connected_peers: network.num_connected_peers(),
				num_active_peers: network.num_active_peers(),
				average_download_per_sec: network.average_download_per_sec(),
				average_upload_per_sec: network.average_upload_per_sec(),
			};
			let state = network.network_state();
			(status, state)
		});

		// Main network polling.
		if let Poll::Ready(Ok(())) = Pin::new(&mut network).poll(cx).map_err(|err| {
			warn!(target: "service", "Error in network: {:?}", err);
		}) {
			return Poll::Ready(());
		}

		// Now some diagnostic for performances.
		let polling_dur = before_polling.elapsed();
		log!(
			target: "service",
			if polling_dur >= Duration::from_secs(1) { Level::Warn } else { Level::Trace },
			"Polling the network future took {:?}",
			polling_dur
		);

		Poll::Pending
	})
}

/// Overview status of the network.
#[derive(Clone)]
pub struct NetworkStatus<B: BlockT> {
	/// Current global sync state.
	pub sync_state: sc_network::SyncState,
	/// Target sync block number.
	pub best_seen_block: Option<NumberFor<B>>,
	/// Number of peers participating in syncing.
	pub num_sync_peers: u32,
	/// Total number of connected peers
	pub num_connected_peers: usize,
	/// Total number of active peers.
	pub num_active_peers: usize,
	/// Downloaded bytes per second averaged over the past few seconds.
	pub average_download_per_sec: u64,
	/// Uploaded bytes per second averaged over the past few seconds.
	pub average_upload_per_sec: u64,
}

impl<TBl, TCl, TSc, TNetStatus, TNet, TTxPool, TOc> Drop for
	Service<TBl, TCl, TSc, TNetStatus, TNet, TTxPool, TOc>
{
	fn drop(&mut self) {
		debug!(target: "service", "Substrate service shutdown");
		if let Some(signal) = self.signal.take() {
			let _ = signal.fire();
		}
	}
}

/// Starts RPC servers that run in their own thread, and returns an opaque object that keeps them alive.
#[cfg(not(target_os = "unknown"))]
fn start_rpc_servers<G, E, H: FnMut() -> sc_rpc_server::RpcHandler<sc_rpc::Metadata>>(
	config: &Configuration<G, E>,
	mut gen_handler: H
) -> Result<Box<dyn std::any::Any + Send + Sync>, error::Error> {
	fn maybe_start_server<T, F>(address: Option<SocketAddr>, mut start: F) -> Result<Option<T>, io::Error>
		where F: FnMut(&SocketAddr) -> Result<T, io::Error>,
	{
		Ok(match address {
			Some(mut address) => Some(start(&address)
				.or_else(|e| match e.kind() {
					io::ErrorKind::AddrInUse |
					io::ErrorKind::PermissionDenied => {
						warn!("Unable to bind RPC server to {}. Trying random port.", address);
						address.set_port(0);
						start(&address)
					},
					_ => Err(e),
				})?),
			None => None,
		})
	}

	Ok(Box::new((
		maybe_start_server(
			config.rpc_http,
			|address| sc_rpc_server::start_http(address, config.rpc_cors.as_ref(), gen_handler()),
		)?,
		maybe_start_server(
			config.rpc_ws,
			|address| sc_rpc_server::start_ws(
				address,
				config.rpc_ws_max_connections,
				config.rpc_cors.as_ref(),
				gen_handler(),
			),
		)?.map(Mutex::new),
	)))
}

/// Starts RPC servers that run in their own thread, and returns an opaque object that keeps them alive.
#[cfg(target_os = "unknown")]
fn start_rpc_servers<G, E, H: FnMut() -> sc_rpc_server::RpcHandler<sc_rpc::Metadata>>(
	_: &Configuration<G, E>,
	_: H
) -> Result<Box<dyn std::any::Any + Send + Sync>, error::Error> {
	Ok(Box::new(()))
}

/// An RPC session. Used to perform in-memory RPC queries (ie. RPC queries that don't go through
/// the HTTP or WebSockets server).
#[derive(Clone)]
pub struct RpcSession {
	metadata: sc_rpc::Metadata,
}

impl RpcSession {
	/// Creates an RPC session.
	///
	/// The `sender` is stored inside the `RpcSession` and is used to communicate spontaneous JSON
	/// messages.
	///
	/// The `RpcSession` must be kept alive in order to receive messages on the sender.
	pub fn new(sender: futures01::sync::mpsc::Sender<String>) -> RpcSession {
		RpcSession {
			metadata: sender.into(),
		}
	}
}

/// Transaction pool adapter.
pub struct TransactionPoolAdapter<C, P> {
	imports_external_transactions: bool,
	pool: Arc<P>,
	client: Arc<C>,
	executor: SpawnTaskHandle,
}

/// Get transactions for propagation.
///
/// Function extracted to simplify the test and prevent creating `ServiceFactory`.
fn transactions_to_propagate<Pool, B, H, E>(pool: &Pool)
	-> Vec<(H, B::Extrinsic)>
where
	Pool: TransactionPool<Block=B, Hash=H, Error=E>,
	B: BlockT,
	H: std::hash::Hash + Eq + sp_runtime::traits::Member + sp_runtime::traits::MaybeSerialize,
	E: IntoPoolError + From<sp_transaction_pool::error::Error>,
{
	pool.ready()
		.filter(|t| t.is_propagateable())
		.map(|t| {
			let hash = t.hash().clone();
			let ex: B::Extrinsic = t.data().clone();
			(hash, ex)
		})
		.collect()
}

impl<B, H, C, Pool, E> sc_network::TransactionPool<H, B> for
	TransactionPoolAdapter<C, Pool>
where
	C: sc_network::ClientHandle<B> + Send + Sync,
	Pool: 'static + TransactionPool<Block=B, Hash=H, Error=E>,
	B: BlockT,
	H: std::hash::Hash + Eq + sp_runtime::traits::Member + sp_runtime::traits::MaybeSerialize,
	E: 'static + IntoPoolError + From<sp_transaction_pool::error::Error>,
{
	fn transactions(&self) -> Vec<(H, B::Extrinsic)> {
		transactions_to_propagate(&*self.pool)
	}

	fn hash_of(&self, transaction: &B::Extrinsic) -> H {
		self.pool.hash_of(transaction)
	}

	fn import(
		&self,
		report_handle: ReportHandle,
		who: PeerId,
		reputation_change_good: sc_network::ReputationChange,
		reputation_change_bad: sc_network::ReputationChange,
		transaction: B::Extrinsic
	) {
		if !self.imports_external_transactions {
			debug!("Transaction rejected");
			return;
		}

		let encoded = transaction.encode();
		match Decode::decode(&mut &encoded[..]) {
			Ok(uxt) => {
				let best_block_id = BlockId::hash(self.client.info().best_hash);
				let import_future = self.pool.submit_one(&best_block_id, uxt);
				let import_future = import_future
					.map(move |import_result| {
						match import_result {
							Ok(_) => report_handle.report_peer(who, reputation_change_good),
							Err(e) => match e.into_pool_error() {
								Ok(sp_transaction_pool::error::Error::AlreadyImported(_)) => (),
								Ok(e) => {
									report_handle.report_peer(who, reputation_change_bad);
									debug!("Error adding transaction to the pool: {:?}", e)
								}
								Err(e) => debug!("Error converting pool error: {:?}", e),
							}
						}
					});

				self.executor.spawn("extrinsic-import", import_future);
			}
			Err(e) => debug!("Error decoding transaction {}", e),
		}
	}

	fn on_broadcasted(&self, propagations: HashMap<H, Vec<String>>) {
		self.pool.on_broadcasted(propagations)
	}

	fn transaction(&self, hash: &H) -> Option<B::Extrinsic> {
		self.pool.ready_transaction(hash).map(|tx| tx.data().clone())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use futures::executor::block_on;
	use sp_consensus::SelectChain;
	use sp_runtime::traits::BlindCheckable;
	use substrate_test_runtime_client::{prelude::*, runtime::{Extrinsic, Transfer}};
	use sc_transaction_pool::{BasicPool, FullChainApi};

	#[test]
	fn should_not_propagate_transactions_that_are_marked_as_such() {
		// given
		let (client, longest_chain) = TestClientBuilder::new().build_with_longest_chain();
		let client = Arc::new(client);
		let pool = Arc::new(BasicPool::new(
			Default::default(),
			Arc::new(FullChainApi::new(client.clone())),
		));
		let best = longest_chain.best_chain().unwrap();
		let transaction = Transfer {
			amount: 5,
			nonce: 0,
			from: AccountKeyring::Alice.into(),
			to: Default::default(),
		}.into_signed_tx();
		block_on(pool.submit_one(&BlockId::hash(best.hash()), transaction.clone())).unwrap();
		block_on(pool.submit_one(&BlockId::hash(best.hash()), Extrinsic::IncludeData(vec![1]))).unwrap();
		assert_eq!(pool.status().ready, 2);

		// when
		let transactions = transactions_to_propagate(&*pool);

		// then
		assert_eq!(transactions.len(), 1);
		assert!(transactions[0].1.clone().check().is_ok());
		// this should not panic
		let _ = transactions[0].1.transfer();
	}
}
