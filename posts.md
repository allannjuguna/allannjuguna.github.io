---
layout: page
permalink: /posts/
title: Posts
---


<div id="archives">
{% for post in site.posts %}
  <h4><a href="{{ site.baseurl }}{{ post.url }}">{{post.title}}</a></h4>
{% endfor %}
</div>