// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! # [DNS name resolution](https://github.com/libp2p/specs/blob/master/addressing/README.md#ip-and-name-resolution)
//! [`Transport`] for libp2p.
//!
//! This crate provides the type [`tokio::Transport`] based on [`hickory_resolver::TokioResolver`].
//!
//! A [`Transport`] is an address-rewriting [`libp2p_core::Transport`] wrapper around
//! an inner `Transport`. The composed transport behaves like the inner
//! transport, except that [`libp2p_core::Transport::dial`] resolves `/dns/...`, `/dns4/...`,
//! `/dns6/...` and `/dnsaddr/...` components of the given `Multiaddr` through
//! a DNS, replacing them with the resolved protocols (typically TCP/IP).
//!
//! The [`tokio::Transport`] is enabled by default under the `tokio` feature.
//! Tokio users can furthermore opt-in to the `tokio-dns-over-rustls` and
//! `tokio-dns-over-https-rustls` features.
//! For more information about these features, please refer to the documentation
//! of [hickory-resolver].
//! Alternative runtimes or resolvers can be used though a manual implementation of [`Resolver`].
//!
//! On Unix systems, if no custom configuration is given, [hickory-resolver]
//! will try to parse the `/etc/resolv.conf` file. This approach comes with a
//! few caveats to be aware of:
//!   1) This fails (panics even!) if `/etc/resolv.conf` does not exist. This is the case on all
//!      versions of Android.
//!   2) DNS configuration is only evaluated during startup. Runtime changes are thus ignored.
//!   3) DNS resolution is obviously done in process and consequently not using any system APIs
//!      (like libc's `gethostbyname`). Again this is problematic on platforms like Android, where
//!      there's a lot of complexity hidden behind the system APIs.
//!
//! If the implementation requires different characteristics, one should
//! consider providing their own implementation of [`Transport`] or use
//! platform specific APIs to extract the host's DNS configuration (if possible)
//! and provide a custom [`ResolverConfig`].
//!
//! [hickory-resolver]: https://docs.rs/hickory-resolver

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

#[cfg(feature = "tokio")]
pub mod tokio {
    use std::sync::Arc;

    use hickory_resolver::{net::runtime::TokioRuntimeProvider, system_conf, TokioResolver};
    use parking_lot::Mutex;

    pub type Transport<T> = crate::transport::Transport<T, TokioResolver>;

    impl<T> Transport<T> {
        pub fn system(inner: T) -> Result<Transport<T>, std::io::Error> {
            let (cfg, opts) = system_conf::read_system_conf()
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            Ok(Self::custom(inner, cfg, opts))
        }

        pub fn custom(
            inner: T,
            cfg: hickory_resolver::config::ResolverConfig,
            opts: hickory_resolver::config::ResolverOpts,
        ) -> Transport<T> {
            Transport {
                inner: Arc::new(Mutex::new(inner)),
                resolver: TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default())
                    .with_options(opts)
                    .build()
                    .expect("valid resolver config should build"),
            }
        }
    }
}

mod transport;
pub use transport::{Error, Resolver, ResolverConfig, ResolverOpts, Transport};

#[cfg(all(test, feature = "tokio"))]
mod tests;
