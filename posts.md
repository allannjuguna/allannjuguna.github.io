---
layout: page
permalink: /posts/
title: Posts
---


<div id="archives">
{% for post in site.posts %}
  <div class="archive-group">
    {% capture post_name %}{{ post | first }}{% endcapture %}
    <div id="#{{ post_name | slugize }}"></div>
    <p></p>

    <h3 class="post-head">{{ post_name }}</h3>
    <a name="{{ post_name | slugize }}"></a>
    {% for post in site.posts[post_name] %}
    <article class="archive-item">
      <h4><a href="{{ site.baseurl }}{{ post.url }}">{{post.title}}</a></h4>
    </article>
    {% endfor %}
  </div>
{% endfor %}
</div>