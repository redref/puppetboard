{%- import '_macros.html' as macros -%}
{
  "draw": {{draw}},
  "recordsTotal": {{total}},
  "recordsFiltered": {{total_filtered}},
  "data": [
    {% for report in reports -%}
      {%- if not loop.first %},{%- endif -%}
      [
        {%- for column in columns -%}
          {%- if not loop.first %},{%- endif -%}
          {%- if column.type == 'datetime' -%}
            "<span rel=\"utctimestamp\">{{ report[column.attr] }}</span>"
          {%- elif column.type == 'status' -%}
            {% filter jsonprint -%}
              {{ macros.report_status(status=report.status, report=report, current_env=current_env) }}
            {%- endfilter %}
          {%- elif column.type == 'node' -%}
            {% filter jsonprint %}<a href="{{url_for('node', env=current_env, node_name=report.node)}}">{{ report.node }}</a>{% endfilter %}
          {%- else -%}
            {{ report[column.attr] | jsonprint }}
          {%- endif -%}
        {%- endfor -%}
      ]
    {% endfor %}
  ]
}
