# Cylon

> “Building secure Clojure web applications needs to be easier, and
> requires integrated security frameworks - not standalone libraries!” –
> John P. Hackworth, [Clojure web security is worse than you think](https://hackworth.be/2014/03/26/clojure-web-security-is-worse-than-you-think/)

An integrated security system for Clojure applications built using
Stuart Sierra's [component](https://github.com/stuartsierra/component).

Cylon provides protected routes, a customisable login form, a salted
hashed HMAC password store with pluggable durability, a persistent
session store, targeted
[Liberator](http://clojure-liberator.github.io/liberator/) support, CSRF
protection and more, by adding a single Cylon component to an existing
[component](https://github.com/stuartsierra/component)-based
application.

## Installation

Add the following dependency to your `project.clj` file

```clojure
[cylon "0.4.0"]
```

## Terms

The precise meanings of the terms component, system-map and system are
those in [component](https://github.com/stuartsierra/component). In
summary, a _component_ is a map of data, usually implemented as a record
with associated protocols specifying functions for start/stop and
others. A _system_ is a set of these components, with the inclusion of
declared dependency references into each component.

## Quick start

To create a modular website integrated with Cylon security comonents, use `lein modular`.

    $ lein new modular myapp +cylon

If you plan to create web APIs, Cylon also offers OAuth2, allowing you
to expose this APIs securely for use by other applications.

Add __`+idp`__ (__+__ __id__entity __p__rovider) if you wish to store

You can add them individually or both together in the same application :-

    $ lein new modular myapp +cylon +idp +rp

## Discussion

Cylon provides an _integrated system_, rather than requiring developers
to roll their own from smaller libraries.

Alternative systems _can_ be created by interchanging components,
providing necessary flexibility for bespoke Clojure applications.

Nevertheless, 'out-of-the-box' defaults should provide good security, on
par with other languages and frameworks. That is what is currently
missing in the Clojure landscape and the gap that Cylon aims to fill.

### Differences with friend

The key difference is that [friend](https://github.com/cemerick/friend)
is designed upon compojure, whereas Cylon is designed upon component,
and is designed specifically for modular applications, where
functionality can be added through the addition of extra components.

Stuart Sierra's component library provides a balanced, elegant and
"essential" foundation for bringing all these parts together into a
single system, so it's a natural fit for this problem. It is also
straight-forward to decompose (and therefore reason about) the system
(by understanding the role that each component plays). This is an
important property of any security system - if the design is difficult
to comprehend but 'just works' or works 'like magic' then it limits the
number of people who can understand it and point out potential
weaknesses.

Ultimately, whether Cylon is right for you will depend on how you build
your Clojure web applications. For smaller applications with a single set
of Compojure routes, friend is a better choice.

For larger applications, especially those with multiple modules and
using [Liberator](http://clojure-liberator.github.io/liberator/) to
provide a fuller REST API, Cylon is a very good fit.

## Pronounication

Cylon is intented to be pronounced as in the 1978 movie of
[Battlestar Gallactica](http://en.wikipedia.org/wiki/Cylon_%28Battlestar_Galactica%29),
with the stress on the first syllable.  It is NOT pronounced 'Ceylon'.





## TODO

Cylon is new. Here's some of the items which will be covered soon or very soon.

* CSRF
* OpenId-Connect
* Persistent sessions

## Limitations

Currently Cylon only supports securing bidi routes and Liberator
resources. We hope to support Compojure routes too, pull requests
definitely accepted.

We don't recommend relying on Cylon for production systems until we
reach version 1.0, which will indicate that Cylon has been deployed into
production elsewhere and has undergone thorough peer review.

## Join in the conversation

Join our Google group cylon-security@googlegroups.com for discussion
about how to improve Cylon.

## References

https://hackworth.be/2014/03/26/clojure-web-security-is-worse-than-you-think/
https://github.com/dhruvchandna/ring-secure-headers
https://github.com/weavejester/ring-anti-forgery

## Acknowledgements

Aaron Bedra's seminal ClojureWest talk in 2014 –
http://www.youtube.com/watch?v=CBL59w7fXw4 - this was the inspiration
between Cylon.

Special thanks to [Mastodon C](http://www.mastodonc.com/) for sponsoring
the development on Cylon, and using it in their kixi projects
[kixi.hecuba](https://github.com/MastodonC/kixi.hecuba) and
[kixi.stentor](https://github.com/MastodonC/kixi.stentor)

Also, to Neale Swinnerton [@sw1nn](https://twitter.com/sw1nn) for the
original work in adopting Stuart's component library and showing how to
migrate [Jig](https://github.com/juxt/jig) components to it.

[Juan Antonio Ruz](https://github.com/tangrammar) designed and developed
the TOTP two-factor authentication support. Additionally Juan conducted
the background research and co-authored the OAuth2 support.

## Copyright & License

The MIT License (MIT)

Copyright © 2014 JUXT LTD.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
