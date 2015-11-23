Name
====

**ngx_http_access_dynamic_module**

This project is still experimental and under early development.

Description
===========

**ngx_http_access_dynamic_module** - one of nginx real-time deny access module. Code 403 should be returned when be denied. Only support no mask ipv4 now. 


*This module is not distributed with the Nginx source.* See [the installation instructions](#installation).


Version
=======

This document describes ngx_http_access_dynamic_module released on Nov.18 2015.

Synopsis
========

This is a nginx  module, which like ngx_http_access_module, only deny in default, mask not support also now.
You can config bellow.
```nginx
 http {

	#the location will be denied
	location /foo {
		access_dynamic;
		...
	}

	#dynamic push ips here, only POST allow, batch 10 ips now.
	location /ips-push {
		access_dynamic_push;
	}

	#check if an ip addree has been denied already
	location /ip-exist {
		access_dynamic_exist;
	}

	#allow an ip address if exist 
	location /ip-del {
		access_dynamic_del;
	}

```



Limitations
===========


Installation
============

Grab the nginx source code from [nginx.org](http://nginx.org/), for example,
the version 1.8.0, and then build the source with this module:

```bash

 wget 'http://nginx.org/download/nginx-1.7.7.tar.gz'
 tar -xzvf nginx-1.8.0.tar.gz
 cd nginx-1.8.0/

 # Here we assume you would install you nginx under /opt/nginx/.
 ./configure --prefix=/opt/nginx \
     --add-module=/path/to/ngx_http_access_dynamic_module

 make
 make install
```

Download the latest version of the release tarball of this module

Authors
=======

* Peiyuan Feng *&lt;fengpeiyuan@gmail.com&gt;*.

This wiki page is also maintained by the author himself, and everybody is encouraged to improve this page as well.

Copyright & License
===================

Copyright (c) 2014-2015, Peiyuan Feng <fengpeiyuan@gmail.com>.

This module is licensed under the terms of the BSD license.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
