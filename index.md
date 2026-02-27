---
layout: default
title: 分类目录
---

# 分类目录

{% assign grouped = site.posts | group_by: "category" %}

{%- comment -%}
先输出配置里指定的分类顺序
{%- endcomment -%}
{% for cat_name in site.category_order %}
  {% assign cat = grouped | where: "name", cat_name | first %}
  {% if cat %}
## {{ cat.name }}

<ul>
  {% for post in cat.items %}
    <li><a href="{{ post.url | relative_url }}">{{ post.title }}</a></li>
  {% endfor %}
</ul>
  {% endif %}
{% endfor %}

{%- comment -%}
再输出那些不在 category_order 里的分类（按名称排序）
{%- endcomment -%}
{% assign ordered_names = site.category_order | join: "||" %}
{% assign extras = grouped | sort: "name" %}
{% for cat in extras %}
  {% unless ordered_names contains cat.name %}
## {{ cat.name }}

<ul>
  {% for post in cat.items %}
    <li><a href="{{ post.url | relative_url }}">{{ post.title }}</a></li>
  {% endfor %}
</ul>
  {% endunless %}
{% endfor %}
