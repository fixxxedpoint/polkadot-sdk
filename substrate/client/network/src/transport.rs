// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Transport that serves as a common ground for all connections.

use either::Either;
use libp2p::{
	core::{
		muxing::StreamMuxerBox,
		transport::{Boxed, OptionalTransport, OrTransport},
		upgrade, StreamMuxer,
	},
	dns::{self, GenDnsConfig},
	identity, noise,
	tcp::{self, tokio::Tcp},
	websocket::{self, WsConfig},
	PeerId, Transport, TransportExt,
};
use std::{ops::SubAssign, sync::Arc, time::Duration};

pub use libp2p::bandwidth::BandwidthSinks;

// use crate::TransportRequirements;

pub trait SecondTypeInPair<T> {
	type SecondInPair;
}

impl<A, B> SecondTypeInPair<(A, B)> for (A, B) {
	type SecondInPair = B;
}

pub trait ConstrainedTransportNG
	where
	Self: Transport<Output = (PeerId, Self::StreamMuxerType)> + Sized + Send + Unpin + 'static,
	Self::Dial: Send + 'static,
	Self::ListenerUpgrade: Send + 'static,
    Self::Error: Send + Sync,
    <Self::StreamMuxerType as StreamMuxer>::Substream: Send + 'static,
	<Self::StreamMuxerType as StreamMuxer>::Error: Send + Sync + 'static,
{
	type StreamMuxerType: StreamMuxer + Send + 'static;
}

impl<T, SM> ConstrainedTransportNG for T
where
	T: Transport<Output = (PeerId, SM)> + Sized + Send + Unpin + 'static,
	T::Dial: Send + 'static,
	T::ListenerUpgrade: Send + 'static,
	T::Error: Send + Sync,
	SM: StreamMuxer + Send + 'static,
	SM::Substream: Send + 'static,
	SM::Error: Send + Sync + 'static,
{
	type StreamMuxerType = SM;
}

pub trait ConstrainedTransport: Transport<
		Output = (PeerId, Self::StreamMuxerType),
	Dial = Self::DialType,
	ListenerUpgrade = Self::ListenerUpgradeType,
	Error = Self::ErrorType,
	> + Sized
	+ Send
	+ Unpin
	+ 'static {
	type SubstreamType: Send + 'static;
	type StreamMuxerErrorType: Send + Sync + 'static;

	type StreamMuxerType: StreamMuxer<Substream = Self::SubstreamType, Error = Self::StreamMuxerErrorType>
		+ Send
		+ 'static;

	// where
	// StreamMuxerType::Substream: Send + 'static,
	// StreamMuxerType::Error: Send + Sync + 'static;

	type DialType: Send + 'static;
	type ListenerUpgradeType: Send + 'static;
	type ErrorType: Send + Sync;

	// type TransportType: Transport<
	// 		Output = (PeerId, Self::StreamMuxerType),
	// 		Dial = Self::DialType,
	// 		ListenerUpgrade = Self::ListenerUpgradeType,
	// 		Error = Self::ErrorType,
	// 	> + Sized
	// 	+ Send
	// 	+ Unpin
	// 	+ 'static;

	// where
	// 	TransportType::Dial: Send + 'static,
	// 	TransportType::ListenerUpgrade: Send + 'static,
	// 	TransportType::Error: Send + Sync;

	// fn cast(self) -> Self::TransportType;
}

impl<T, SM> ConstrainedTransport for T
where
	T: Transport<Output = (PeerId, SM)> + Sized + Send + Unpin + 'static,
	T::Dial: Send + 'static,
	T::ListenerUpgrade: Send + 'static,
	T::Error: Send + Sync,
	SM: StreamMuxer + Send + 'static,
	SM::Substream: Send + 'static,
	SM::Error: Send + Sync + 'static,
{
	type SubstreamType = SM::Substream;
	type StreamMuxerErrorType = SM::Error;

	type DialType = T::Dial;
	type ListenerUpgradeType = T::ListenerUpgrade;
	type ErrorType = T::Error;

	type StreamMuxerType = SM;
	// type TransportType = T;

	// fn cast(self) -> Self::TransportType {
	// 	self
	// }
}

// pub trait TransportType {
// 	type TransportType;

// 	fn cast(self) -> Self::TransportType;
// }

// impl<T> TransportType for T {
// 	type TransportType = T;

// 	fn cast(self) -> Self::TransportType {
// 		self
// 	}
// }

/// Builds the transport that serves as a common ground for all connections.
///
/// If `memory_only` is true, then only communication within the same process are allowed. Only
/// addresses with the format `/memory/...` are allowed.
///
/// `yamux_window_size` is the maximum size of the Yamux receive windows. `None` to leave the
/// default (256kiB).
///
/// `yamux_maximum_buffer_size` is the maximum allowed size of the Yamux buffer. This should be
/// set either to the maximum of all the maximum allowed sizes of messages frames of all
/// high-level protocols combined, or to some generously high value if you are sure that a maximum
/// size is enforced on all high-level protocols.
///
/// Returns a multiplexed and authenticated implementation of [`libp2p::Transport``].
pub fn build_default_transport(
	keypair: identity::Keypair,
	memory_only: bool,
	yamux_window_size: Option<u32>,
	yamux_maximum_buffer_size: usize,
) -> impl ConstrainedTransport {
	// Build the base layer of the transport.
	let transport = if !memory_only {
		// Main transport: DNS(TCP)
		let tcp_config = tcp::Config::new().nodelay(true);
		let tcp_trans = tcp::tokio::Transport::new(tcp_config.clone());
		let dns_init = dns::TokioDnsConfig::system(tcp_trans);

		Either::Left(if let Ok(dns) = dns_init {
			// WS + WSS transport
			//
			// Main transport can't be used for `/wss` addresses because WSS transport needs
			// unresolved addresses (BUT WSS transport itself needs an instance of DNS transport to
			// resolve and dial addresses).
			let tcp_trans = tcp::tokio::Transport::new(tcp_config);
			let dns_for_wss = dns::TokioDnsConfig::system(tcp_trans)
				.expect("same system_conf & resolver to work");
			Either::Left(websocket::WsConfig::new(dns_for_wss).or_transport(dns))
		} else {
			// In case DNS can't be constructed, fallback to TCP + WS (WSS won't work)
			let tcp_trans = tcp::tokio::Transport::new(tcp_config.clone());
			let desktop_trans = websocket::WsConfig::new(tcp_trans)
				.or_transport(tcp::tokio::Transport::new(tcp_config));
			Either::Right(desktop_trans)
		})
	} else {
		Either::Right(OptionalTransport::some(libp2p::core::transport::MemoryTransport::default()))
	};

	let authentication_config = noise::Config::new(&keypair).expect("Can create noise config. qed");
	let multiplexing_config = {
		let mut yamux_config = libp2p::yamux::Config::default();
		// Enable proper flow-control: window updates are only sent when
		// buffered data has been consumed.
		yamux_config.set_window_update_mode(libp2p::yamux::WindowUpdateMode::on_read());
		yamux_config.set_max_buffer_size(yamux_maximum_buffer_size);

		if let Some(yamux_window_size) = yamux_window_size {
			yamux_config.set_receive_window_size(yamux_window_size);
		}

		yamux_config
	};

	transport
		.upgrade(upgrade::Version::V1Lazy)
		.authenticate(authentication_config)
		.multiplex(multiplexing_config)
		.timeout(Duration::from_secs(20))
}

/// Builds the transport that serves as a common ground for all connections.
///
/// If `memory_only` is true, then only communication within the same process are allowed. Only
/// addresses with the format `/memory/...` are allowed.
///
/// `yamux_window_size` is the maximum size of the Yamux receive windows. `None` to leave the
/// default (256kiB).
///
/// `yamux_maximum_buffer_size` is the maximum allowed size of the Yamux buffer. This should be
/// set either to the maximum of all the maximum allowed sizes of messages frames of all
/// high-level protocols combined, or to some generously high value if you are sure that a maximum
/// size is enforced on all high-level protocols.
///
/// Returns a `BandwidthSinks` object that allows querying the average bandwidth produced by all
/// the connections spawned with this transport.
pub fn build_transport(
	keypair: identity::Keypair,
	memory_only: bool,
	yamux_window_size: Option<u32>,
	yamux_maximum_buffer_size: usize,
) -> (Boxed<(PeerId, StreamMuxerBox)>, Arc<BandwidthSinks>) {
	build_default_transport(keypair, memory_only, yamux_window_size, yamux_maximum_buffer_size)
		.boxed()
		.with_bandwidth_logging()
}
