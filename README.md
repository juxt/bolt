# Cylon

> “Building secure Clojure web applications needs to be easier, and
> requires integrated security frameworks - not standalone libraries!” –
> John P. Hackworth, [Clojure web security is worse than you think](https://hackworth.be/2014/03/26/clojure-web-security-is-worse-than-you-think/)

An integrated security system for Clojure applications based on a set of components written to the specifications of Stuart Sierra's [component](https://github.com/stuartsierra/component).

Currently, Cylon represents merely an idea. This idea is to separate all
security-related concerns from Clojure applications, so that they can be
implemented in library form.

That said, Cylon is under constant development towards delivering
practical benefit for Clojure web applications.

## Terms

The precise meanings of the terms component, system-map and system are
those in [component](https://github.com/stuartsierra/component). In
summary, a _component_ is a map of data, usually implemented as a record
with associated protocols specifying functions for start/stop and
others. A _system_ is a set of these components, with the inclusion of
declared dependency references into each component.

In addition, Cylon uses the following terms

* username - a user's short identifier, for example: __bob__
* email - a user's email address
* user - a map, containing entries that distinguish and describe a user

## Discussion

Cylon provides an _integrated system_ of components, rather than requiring developers
to roll their own from smaller libraries.

Functionality can be customised by interchanging components, providing
necessary flexibility for bespoke Clojure applications.

Nevertheless, 'out-of-the-box' defaults should provide good security, on
par with other languages and frameworks. That is what is currently
missing in the Clojure landscape and the gap that Cylon aims to fill.

### Differences with Friend

The key difference between Cylon and Friend is that Cylon is designed
for use with [Component](https://github.com/stuartsierra/component)
based applications.

Cylon is designed specifically for modular applications, where
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

To provide flexibility, Cylon fully embraces and consistently adopts
_protocol polymorphism_ within Clojure, enabled by Stuart's
approach. This will not to everyone's taste. Alternatives, such as the
use of dynamic vars, are wholly avoided. Functional programming is a
beautiful thing in the small, but presents practical challenges at
scale. Polymorphism is one of the cornerstones of object orientation
worth stealing.

### Should you use Cylon?

Ultimately, whether Cylon is right for you will depend on how you build
your Clojure web applications. For smaller applications with a single
set of Compojure routes, Friend is a better choice.

For larger applications, especially those with multiple modules and
using [Liberator](http://clojure-liberator.github.io/liberator/) or
[yada](https://github.com/juxt/yada) to provide a fuller REST API, Cylon
should be a good fit.

## Pronounication

Cylon is intented to be pronounced as in the 1978 movie of
[Battlestar Gallactica](http://en.wikipedia.org/wiki/Cylon_%28Battlestar_Galactica%29),
with the stress on the first syllable.  It is NOT pronounced 'Ceylon'.

## Limitations

Cylon is not suitable for production systems until it reaches
version 1.0, which will indicate that Cylon has been deployed into
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
behind Cylon.

[Mastodon C](http://www.mastodonc.com/) for sponsoring the development
on Cylon, and using it in their kixi projects
[kixi.hecuba](https://github.com/MastodonC/kixi.hecuba) and
[kixi.stentor](https://github.com/MastodonC/kixi.stentor)

Also, to Neale Swinnerton [@sw1nn](https://twitter.com/sw1nn) for the
original work in adopting Stuart's component library and showing how to
migrate [Jig](https://github.com/juxt/jig) components to it.

[Yodit Stanton](https://github.com/yods) and the rest of the
[opensensors.io](https://opensensors.io) team for putting up with the
regular Cylon updates and being the first adopters of the OAuth2
features.

[Juan Antonio Ruz](https://github.com/tangrammar) for designing and
developing the TOTP two-factor authentication support. Additionally Juan
conducted the background research and co-authored the OAuth2 support,
and many other aspects of the project. Also for providing a public
example of how to use Cylon.

[Martin Trojer](https://github.com/martintrojer) and others from
[JUXT](https://github.com/juxt) for a continual stream of
thought-provoking ideas and good advice.

[Andrey Antukh](https://github.com/niwibe) for suggestions about
integration with [Buddy](https://github.com/niwibe/buddy).

## Copyright & License

The MIT License (MIT)

Copyright © 2014 JUXT LTD.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
