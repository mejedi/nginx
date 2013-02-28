
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

/*
 * Though it is compeling to play clever i.e. to avoid memcpy as much as
 * possible and to reuse parts of input buffers in the output chain it
 * makes the code unnecessary hard to debug and maintain.  For this
 * reasons we write output to the new (recycled) buffer.  We believe
 * that the cost of pattern matching exceeds memcpy overhead.
 *
 * In order to perform pattern matching we need a sliding window over
 * the input.  Matching algorithm may save and restore positions
 * effectively passing multiple times over the same byte evaluating
 * different possibilities.  It is too inconvenient to get concerned
 * with buffer boundaries or to accomodate for multiple data sources
 * (i.e. current buffer/a copy of the previous buffer).  For this reasons
 * we first copy a portion of input to the circular buffer and run
 * matching algorithm on the circular buffer.
 *
 * Matching algorithm is a simplified variant of FSM-driven regex
 * search.  Only literal patterns are supported.
 *
 * nickz
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_http_sub_fsm_s  ngx_http_sub_fsm_t;


typedef struct {
    ngx_str_t                  match;
    ngx_http_complex_value_t   value;

    ngx_hash_t                 types;

    ngx_flag_t                 once;

    ngx_array_t               *types_keys;

    ngx_http_sub_fsm_t        *fsm;
    size_t                     match_max;

} ngx_http_sub_loc_conf_t;


typedef enum {

    init_state,
    accumulate_state,
    search_state,
    trim_cb_state,
    replace_state,
    repl_write_state,
    flush_cb_state,
    final_state

} ngx_http_sub_state_t;


typedef struct {
    /* circular buffer-fu */
    u_char                    *cb_p;
    size_t                     cb_begin;
    size_t                     cb_end;
    size_t                     cb_mask;

    /* state */
    int                        s;
    u_char                    *in_pos;
    size_t                     search_pos;
    ngx_http_sub_fsm_t        *fsm;
    int                        match_idx; /* -1: no match */
    size_t                     match_pos;
    u_char                    *repl_begin;
    u_char                    *repl_end;

    ngx_chain_t               *in;
    ngx_chain_t                out;
    ngx_buf_t                  obuf;
    int                        busy;
    ngx_int_t                  rc;

    ngx_str_t                  sub;

} ngx_http_sub_ctx_t;


struct ngx_http_sub_fsm_s {
    int                        match_idx;
    u_char                     dispatch[256];
    ngx_http_sub_fsm_t        *links[1];
};


static size_t ngx_http_sub_output(ngx_http_request_t *r,
    ngx_http_sub_ctx_t *ctx, u_char *p, size_t sz);
static int ngx_http_sub_output_cb(ngx_http_request_t *r,
    ngx_http_sub_ctx_t *ctx, size_t end_pos);

static char * ngx_http_sub_filter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_sub_create_conf(ngx_conf_t *cf);
static char *ngx_http_sub_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_sub_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_sub_filter_commands[] = {

    { ngx_string("sub_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_sub_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("sub_filter_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sub_loc_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("sub_filter_once"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sub_loc_conf_t, once),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_sub_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_sub_filter_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_sub_create_conf,              /* create location configuration */
    ngx_http_sub_merge_conf                /* merge location configuration */
};


ngx_module_t  ngx_http_sub_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_sub_filter_module_ctx,       /* module context */
    ngx_http_sub_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_sub_header_filter(ngx_http_request_t *r)
{
    ngx_http_sub_ctx_t        *ctx;
    ngx_http_sub_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_sub_filter_module);

    if (slcf->match.len == 0
        || r->headers_out.content_length_n == 0
        || ngx_http_test_content_type(r, &slcf->types) == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_sub_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    size_t sz = 512;
    while (sz < slcf->match_max * 4) {
        sz *= 2;
    }

    ctx->cb_p = ngx_pnalloc(r->pool, sz);
    if (!ctx->cb_p) {
        return NGX_ERROR;
    }
    ctx->cb_mask = sz-1;
    ctx->cb_begin = ctx->cb_end = -100; /* test wrap around */

    ctx->s = init_state;
    ctx->search_pos = ctx->cb_begin;
    ctx->fsm = slcf->fsm;
    ctx->match_idx = -1;

    ctx->out.buf = &ctx->obuf;
    ctx->obuf.memory = 1;
    ctx->obuf.recycled = 1;
    ctx->obuf.start = ngx_pnalloc(r->pool, 0x10000);
    if (!ctx->obuf.start) {
        return NGX_ERROR;
    }
    ctx->obuf.end = ctx->obuf.start + 0x10000;
    ctx->obuf.pos = ctx->obuf.last = ctx->obuf.start;

    ngx_http_set_ctx(r, ctx, ngx_http_sub_filter_module);

    r->filter_need_in_memory = 1;
    r->buffered |= NGX_HTTP_SUB_BUFFERED;

    if (r == r->main) {
        ngx_http_clear_content_length(r);
        ngx_http_clear_last_modified(r);
        ngx_http_clear_etag(r);
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_sub_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_sub_ctx_t        *ctx;
    ngx_http_sub_loc_conf_t   *slcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_sub_filter_module);

    if (ctx == NULL || ctx->s == final_state) {
        return ngx_http_next_body_filter(r, in);
    }

    /* add the incoming chain to the chain ctx->in */

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http sub filter \"%V\"", &r->uri);

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_sub_filter_module);

    while (1) {

        switch (ctx->s) {
        case init_state:
            {
                if (!ctx->in) {
                    return NGX_OK;
                }
                ctx->in_pos = ctx->in->buf->pos;
                ctx->s = accumulate_state;
            }
            /* fallthrough */
        case accumulate_state:
            {
                size_t avail = ctx->in->buf->last - ctx->in_pos;
                size_t capacity = ctx->cb_mask + 1 - (ctx->cb_end - ctx->cb_begin);
                size_t xfer = (capacity <= avail ? capacity : avail);
                size_t cont = ((ctx->cb_end + ctx->cb_mask) & ~ctx->cb_mask) - ctx->cb_end;

                /* copy xfer amount of data to cb from the buf */
                if (xfer <= cont) {
                    memcpy(
                        &ctx->cb_p[ctx->cb_end & ctx->cb_mask], ctx->in_pos, xfer);
                } else {
                    memcpy(
                        ctx->cb_p, ctx->in_pos + cont, xfer - cont);
                    memcpy(
                        &ctx->cb_p[ctx->cb_end & ctx->cb_mask], ctx->in_pos, cont);
                }
                ctx->cb_end += xfer;
                ctx->in_pos += xfer;

                /* cb full OR all buf data copied into cb AND buf is
                 * the last in chain */
                if (capacity <= avail || ctx->in->buf->last_buf) {
                    ctx->s = search_state;
                    continue;
                }

                if (avail == 0) {
                    /* FIXME reuse chain link */
                    ctx->in->buf->pos = ctx->in->buf->last;
                    ctx->in = ctx->in->next;

                    if (!ctx->in) {
                        ctx->s = init_state;
                        return NGX_OK;
                    }

                    ctx->in_pos = ctx->in->buf->pos;
                    continue;
                }

                continue;
            }
        case search_state:
            {
                int i;

                while (1) {
                    if (ctx->search_pos == ctx->cb_end) {
                        if (ctx->in_pos == ctx->in->buf->last && ctx->in->buf->last_buf) {
                            ctx->s = (ctx->match_idx==-1 ? flush_cb_state : replace_state);
                        } else {
                            ctx->s = trim_cb_state;
                        }
                        break;
                    }

                    i = ctx->fsm->dispatch[ctx->cb_p[ctx->search_pos & ctx->cb_mask]];
                    ctx->fsm = ctx->fsm->links[i];
                    ctx->search_pos++;

                    if (i > 0) {
                        if (ctx->fsm->match_idx != -1) {
                            ctx->match_pos = ctx->search_pos;
                            ctx->match_idx = ctx->fsm->match_idx;
                        }
                    } else {
                        if (ctx->match_idx != -1) {
                            ctx->s = replace_state;
                            break;
                        }
                    }
                }
                continue;
            }
        case trim_cb_state:
            {
                if (ctx->cb_end - ctx->cb_begin > slcf->match_max) {
                    if (!ngx_http_sub_output_cb(
                            r, ctx, ctx->cb_end - slcf->match_max)) {
                        return ctx->rc;
                    }
                }
                ctx->s = accumulate_state;
                continue;
            }
        case replace_state:
            {
                size_t end_pos = ctx->match_pos - slcf->match.len;

                if (!ngx_http_sub_output_cb(r, ctx, end_pos)) {
                    return ctx->rc;
                }
                ctx->cb_begin = ctx->match_pos;

                if (!ctx->sub.data)
                {
                    if (ngx_http_complex_value(
                            r, &slcf->value, &ctx->sub) != NGX_OK) {
                        return NGX_ERROR;
                    }
                }

                ctx->s = repl_write_state;
                ctx->repl_begin = ctx->sub.data;
                ctx->repl_end = ctx->sub.data + ctx->sub.len;
            }
            /* fallthrough */
        case repl_write_state:
            {
                ctx->repl_begin += ngx_http_sub_output(
                    r, ctx, ctx->repl_begin, ctx->repl_end - ctx->repl_begin);

                if (ctx->repl_begin != ctx->repl_end) {
                    return ctx->rc;
                }

                if (!slcf->once) {
                    ctx->search_pos = ctx->cb_begin;
                    ctx->match_idx = -1;
                    ctx->fsm = slcf->fsm;
                    ctx->s = accumulate_state;
                    continue;
                }
            }
            /* fallthrough */
        case flush_cb_state:
            {
                ngx_buf_t *b;
                ngx_chain_t *cl;

                if (!ngx_http_sub_output_cb(r, ctx, ctx->cb_end)) {
                    return ctx->rc;
                }

                if (ctx->obuf.pos == ctx->obuf.last) {
                    ctx->obuf.sync = 1;
                    ctx->obuf.memory = 0;
                    ctx->obuf.recycled = 0;
                }

                b = ctx->in->buf;
                cl = &ctx->out;
                if (ctx->in_pos == b->last) {
                    cl->next = ctx->in->next;
                    ctx->obuf.last_buf = b->last_buf;
                } else {
                    cl->next = ctx->in;
                    if (b->in_file) {
                        b->file_pos += ctx->in_pos - b->pos;
                    }
                }
                b->pos = ctx->in_pos;

                ctx->s = final_state;
                r->buffered &= ~NGX_HTTP_SUB_BUFFERED;
                return ngx_http_next_body_filter(r, cl);
            }
        }
    }
}


static size_t
ngx_http_sub_output(ngx_http_request_t *r, ngx_http_sub_ctx_t *ctx,
    u_char *p, size_t sz)
{
    size_t avail;
    ngx_buf_t *b = &ctx->obuf;

    if (ctx->rc == NGX_ERROR) {
        return 0;
    }

    if (ctx->busy) {
        if (b->pos == b->last) {
            ctx->busy = 0;
            b->pos = b->last = b->start;
        } else {
            return 0;
        }
    }

    avail = b->end - b->last;
    if (sz > avail) {
        memcpy(b->last, p, avail);
        b->last += avail;
        ctx->busy = 1;
        ctx->rc = ngx_http_next_body_filter(r, &ctx->out);
        return avail;
    }

    memcpy(b->last, p, sz);
    b->last += sz;
    return sz;
}


static int
ngx_http_sub_output_cb(ngx_http_request_t *r, ngx_http_sub_ctx_t *ctx,
    size_t end_pos)
{
    size_t split_pt = (ctx->cb_begin + ctx->cb_mask) & ~ctx->cb_mask;

    if (split_pt - ctx->cb_begin < end_pos - ctx->cb_begin) {
        ctx->cb_begin += ngx_http_sub_output(
            r, ctx,
            &ctx->cb_p[ctx->cb_begin & ctx->cb_mask],
            split_pt - ctx->cb_begin);
        ctx->cb_begin += ngx_http_sub_output(r, ctx, ctx->cb_p, end_pos - split_pt);
    } else {
        ctx->cb_begin += ngx_http_sub_output(
            r, ctx,
            &ctx->cb_p[ctx->cb_begin & ctx->cb_mask],
            end_pos - ctx->cb_begin);
    }
    return ctx->cb_begin == end_pos;
}


static char *
ngx_http_sub_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sub_loc_conf_t *slcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    if (slcf->match.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_strlow(value[1].data, value[1].data, value[1].len);

    slcf->match = value[1];

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &slcf->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_sub_create_conf(ngx_conf_t *cf)
{
    ngx_http_sub_loc_conf_t  *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sub_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->match = { 0, NULL };
     *     conf->sub = { 0, NULL };
     *     conf->sub_lengths = NULL;
     *     conf->sub_values = NULL;
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    slcf->once = NGX_CONF_UNSET;

    return slcf;
}


static char *
ngx_http_sub_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_sub_loc_conf_t *prev = parent;
    ngx_http_sub_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->once, prev->once, 1);
    ngx_conf_merge_str_value(conf->match, prev->match, "");

    if (conf->match.len != 0) {
        u_char *p = conf->match.data, *e = p + conf->match.len;
        ngx_http_sub_fsm_t *sm, **ss = &conf->fsm;

        while (1) {
            *ss = sm = ngx_pcalloc(cf->pool, offsetof(ngx_http_sub_fsm_t, links) + sizeof(void *)*2);
            if (!sm) {
                return NGX_CONF_ERROR;
            }
            sm->links[0] = conf->fsm;
            sm->match_idx = -1;

            if (p == e) {
                sm->match_idx = 0;
                break;
            } else {
                sm->dispatch[*p] = 1;
                sm->dispatch[ngx_tolower(*p)] = 1;
                sm->dispatch[ngx_toupper(*p)] = 1;
                p++;
                ss = &sm->links[1];
            }
        }

        conf->match_max = conf->match.len;
    }

    if (conf->value.value.data == NULL) {
        conf->value = prev->value;
    }

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_sub_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_sub_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_sub_body_filter;

    return NGX_OK;
}
