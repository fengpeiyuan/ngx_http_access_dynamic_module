#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define DICT_BUCKET_CAPACITY 10000
#define DICT_CAPACITY 20000
#define PUSH_BATCH_SIZE 10

typedef struct {
    ngx_flag_t enable;
    ngx_shm_zone_t *shm_zone;
} ngx_http_access_dynamic_main_conf_t;

typedef struct {
    char addr_text[256];
    in_addr_t mask;
    in_addr_t addr;
    ngx_int_t next;
    ngx_int_t pre;
    ngx_int_t sequence;
} ngx_http_access_dynamic_dict_bucket_item;

typedef struct {
	ngx_int_t bucket_idx[DICT_CAPACITY];
	ngx_int_t last_used_bucket;
	ngx_http_access_dynamic_dict_bucket_item bucket_arr[DICT_BUCKET_CAPACITY];
} ngx_http_access_dynamic_shctx_t;

typedef struct {
	ngx_http_access_dynamic_shctx_t  *shm;
    ngx_slab_pool_t             *shpool;
} ngx_http_access_dynamic_ctx_t;


static void *ngx_http_access_dynamic_create_main_conf(ngx_conf_t *cf);
//static char *ngx_http_access_dynamic_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_access_dynamic_push_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_access_dynamic_push_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_access_dynamic_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_access_dynamic_handler(ngx_http_request_t *r);
static char *ngx_http_access_dynamic_exist_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_access_dynamic_exist_handler(ngx_http_request_t *r);
static char *ngx_http_access_dynamic_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_access_dynamic_init_zone (ngx_shm_zone_t *shm_zone, void *data);
void ngx_http_access_dynamic_push_post_handler(ngx_http_request_t *r);
static ngx_int_t insert_into_dict(ngx_http_access_dynamic_ctx_t  *ctx, ngx_str_t ipaddr,ngx_cidr_t *cidr);
static ngx_int_t search_from_dict(ngx_http_access_dynamic_ctx_t  *ctx, ngx_str_t *ipaddr);
static char *ngx_http_access_dynamic_del_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_access_dynamic_del_handler(ngx_http_request_t *r);

static ngx_command_t ngx_http_access_dynamic_commands[] = {
	{
			ngx_string("access_dynamic"),
			NGX_HTTP_LOC_CONF|NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
			ngx_http_access_dynamic_enable,
			NGX_HTTP_MAIN_CONF_OFFSET,
			0,
			NULL
	},
	{
			ngx_string("access_dynamic_push"),
			NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
			ngx_http_access_dynamic_push_command,
			NGX_HTTP_LOC_CONF_OFFSET,
			0,
			NULL
	},
	{
			ngx_string("access_dynamic_exist"),
			NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
			ngx_http_access_dynamic_exist_command,
			NGX_HTTP_LOC_CONF_OFFSET,
			0,
			NULL
	},
	{
			ngx_string("access_dynamic_del"),
			NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
			ngx_http_access_dynamic_del_command,
			NGX_HTTP_LOC_CONF_OFFSET,
			0,
			NULL
	},
    ngx_null_command
};

static ngx_http_module_t  ngx_http_access_dynamic_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_access_dynamic_init,
    ngx_http_access_dynamic_create_main_conf,/* create main configuration */
    NULL,                                  /* init main configuration */
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    NULL, /* create location configuration */
    NULL   /* merge location configuration */
};

ngx_module_t  ngx_http_access_dynamic_module = {
    NGX_MODULE_V1,
    &ngx_http_access_dynamic_ctx, /* module context */
    ngx_http_access_dynamic_commands,    /* module directives */
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

static void *
ngx_http_access_dynamic_create_main_conf(ngx_conf_t *cf){
	ngx_http_access_dynamic_main_conf_t  *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_access_dynamic_main_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->enable = NGX_CONF_UNSET;
    return conf;
}

//static char *
//ngx_http_access_dynamic_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child){
//    ngx_http_access_dynamic_main_conf_t *prev = parent;
//    ngx_http_access_dynamic_main_conf_t *conf = child;
//    if (conf->shm_zone == NULL) {
//           conf->shm_zone = prev->shm_zone;
//    }
//    ngx_conf_merge_value(conf->enable, prev->enable, 0);
//    return NGX_CONF_OK;
//}

static char *
ngx_http_access_dynamic_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	ngx_http_access_dynamic_main_conf_t *main_conf;
	ngx_shm_zone_t            *shm_zone;
	ngx_http_access_dynamic_ctx_t  *ctx;
	ngx_str_t        *value;

	main_conf = conf;
    value = cf->args->elts;

    if(ngx_strcasecmp(value[1].data, (u_char *) "on") == 0) {
    	main_conf->enable = 1;
    }else if(ngx_strcasecmp(value[1].data, (u_char *) "off") == 0) {
        	main_conf->enable = 0;
    }else{
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"invalid value \"%s\" in \"%s\" directive,it must be \"on\" or \"off\"",value[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }

	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_access_dynamic_ctx_t));
	if (ctx == NULL) {
		return NGX_CONF_ERROR;
	}

	ngx_str_t shm_name = ngx_string("access_dynamic_shm");
	size_t shm_size = 2*sizeof(ngx_http_access_dynamic_shctx_t);
	shm_zone = ngx_shared_memory_add(cf, &shm_name, shm_size,&ngx_http_access_dynamic_module);
	if (shm_zone == NULL) {
		return NGX_CONF_ERROR;
	}
	if (shm_zone->data) {
	    ctx = shm_zone->data;
	    shm_zone->init = ngx_http_access_dynamic_init_zone;
	    main_conf->shm_zone = shm_zone;
	    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,"%V is already bound to she_zone \"%V\"",&cmd->name, &shm_name);
	    return NGX_CONF_OK;
	}
	shm_zone->init = ngx_http_access_dynamic_init_zone;
	shm_zone->data = ctx;
	main_conf->shm_zone = shm_zone;
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_access_dynamic_init_zone (ngx_shm_zone_t *shm_zone, void *data){
	ngx_http_access_dynamic_ctx_t  *octx = data;
	size_t                     len;
	ngx_http_access_dynamic_ctx_t  *ctx;
	ctx = shm_zone->data;
    if (octx) {
	        ctx->shm = octx->shm;
	        ctx->shpool = octx->shpool;
	        return NGX_OK;
    }
	ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
	if (shm_zone->shm.exists) {
	        ctx->shm = ctx->shpool->data;
	        ctx->shpool = octx->shpool;
	        return NGX_OK;
	}
    ctx->shm = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_access_dynamic_shctx_t));
	if (ctx->shm == NULL) {
	    return NGX_ERROR;
	}
	ngx_memset(ctx->shm, 0, sizeof(ngx_http_access_dynamic_shctx_t));
	ngx_int_t loop;
	for (loop = 0; loop < DICT_CAPACITY; loop++) {
	        ctx->shm->bucket_idx[loop] = -1;
	}
	ctx->shm->last_used_bucket = -1;
	for (loop = 0; loop < DICT_BUCKET_CAPACITY; loop++) {
	        ctx->shm->bucket_arr[loop].next = -1;
	}
    ctx->shpool->data = ctx->shm;
    len = sizeof("in share zone:") + shm_zone->shm.name.len;
	ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
	if (ctx->shpool->log_ctx == NULL) {
	        return NGX_ERROR;
	}
	ngx_sprintf(ctx->shpool->log_ctx, "in share zone:%V",&shm_zone->shm.name);
	ctx->shpool->log_nomem = 0;
    return NGX_OK;
}


static char *
ngx_http_access_dynamic_push_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	ngx_http_core_loc_conf_t  *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_access_dynamic_push_handler;
	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_access_dynamic_push_handler(ngx_http_request_t *r){
	ngx_int_t rc;
	if (!(r->method & NGX_HTTP_POST))	{
		return NGX_HTTP_NOT_ALLOWED;
	}
	rc = ngx_http_read_client_request_body(r, ngx_http_access_dynamic_push_post_handler);
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"\n ngx_http_access_dynamic_push_handler rc:%d ]\n",rc);
	if (rc > NGX_HTTP_SPECIAL_RESPONSE)	{
		    return rc;
	}
	return NGX_DONE;
}

void
ngx_http_access_dynamic_push_post_handler(ngx_http_request_t *r){
	ngx_int_t rc;
	u_char *body;
	size_t body_size;
	ngx_chain_t *ch;
	ngx_array_t *ipstr_arr;
	ngx_array_t *ipstr_invalid_arr;
	u_char *last_cpy = NULL;
	ngx_uint_t loop;
	ngx_http_access_dynamic_main_conf_t *main_conf;
	ngx_http_access_dynamic_ctx_t *ctx;
	ngx_chain_t *out;
	ngx_buf_t *b;

	main_conf = ngx_http_get_module_main_conf(r, ngx_http_access_dynamic_module);
	ctx = main_conf->shm_zone->data;

	/*1.split ip addr(ipv4 support only now) from request body and build ngx_array_t*/
	ngx_http_request_body_t *rb = r->request_body;
	if (rb == NULL) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	body_size = 0;
	for (ch = rb->bufs; ch; ch = ch->next) {
		ngx_buf_t *b = ch->buf;
	    ngx_int_t len = b->last - b->pos;
	    body_size += len;
	}
	if(body_size<=0){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,  "body_size less than 0");
		goto GO_DONE;
	}
	body = ngx_pcalloc(r->pool,body_size);
	if(body==NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,  "body is NULL");
		goto GO_DONE;
	}
	last_cpy = body;
	for (ch = rb->bufs; ch; ch = ch->next) {
			ngx_buf_t *b = ch->buf;
		    ngx_int_t len = b->last - b->pos;
		    last_cpy = ngx_cpymem(last_cpy,b->pos,len);
	}
	ipstr_arr = ngx_array_create(r->pool, PUSH_BATCH_SIZE, sizeof(ngx_str_t));
	ipstr_invalid_arr = ngx_array_create(r->pool, PUSH_BATCH_SIZE, sizeof(ngx_str_t));
   	u_char *split_pos_last = body;
	char separator = '&';
	u_char *split_pos;
	for(loop=0;loop<PUSH_BATCH_SIZE;loop++){
	    		split_pos = ngx_strlchr(split_pos_last,body+body_size,separator);
	    		if(split_pos){
	    			size_t len = split_pos - split_pos_last;
					ngx_str_t *ipstr = ngx_array_push(ipstr_arr);
					ipstr->data = (u_char *)split_pos_last;
					ipstr->len = len;
					split_pos_last = split_pos + 1;
	    		}else{
	    			size_t len = body + body_size - split_pos_last;;
	    			ngx_str_t *ipstr = ngx_array_push(ipstr_arr);
	    			ipstr->data = (u_char *)split_pos_last;
	    			ipstr->len = len;
	    			break;
	    		}
	  }

	  /*2.valid ip addr and insert into dic, invalid into ipstr_invalid_arr*/
	  ngx_str_t *value=(ngx_str_t *)ipstr_arr->elts;
	  for(loop=0;loop<ipstr_arr->nelts;loop++){
	    		ngx_str_t ipstr = value[loop];
	    		ngx_cidr_t cidr;
	    		ngx_memzero(&cidr, sizeof(ngx_cidr_t));
	    		rc = ngx_ptocidr(&ipstr, &cidr);
	    		if (rc == NGX_ERROR) {
	    			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "invalid parameter \"%V\"", &ipstr);
	    			ngx_str_t *ipstr_invalid = ngx_array_push(ipstr_invalid_arr);
	    			ipstr_invalid->data = ipstr.data;
	    			ipstr_invalid->len = ipstr.len;
	    			continue;
	    		}
	    		if (rc == NGX_DONE) {
	    			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,  "low address bits of %V are meaningless", &ipstr);
	    			ngx_str_t *ipstr_invalid = ngx_array_push(ipstr_invalid_arr);
	    			ipstr_invalid->data = ipstr.data;
	    			ipstr_invalid->len = ipstr.len;
	    			continue;
	    		}

	    		if (cidr.family == AF_INET) {
	    			insert_into_dict(ctx,ipstr,&cidr);
	    		}

	 }

	 /*3.print result */
	 ngx_str_set(&r->headers_out.content_type,"text/plain");
	 out = ngx_alloc_chain_link(r->pool);
	 if(out == NULL){
	   	return ;
	 }
	 if(ipstr_invalid_arr->nelts>0){
	    		ngx_int_t invalid_size = 0;
	    		ngx_str_t *value=(ngx_str_t *)ipstr_invalid_arr->elts;
	    		for(loop=0;loop<ipstr_invalid_arr->nelts;loop++){
	    			ngx_str_t invalid_ipstr = value[loop];
	    			invalid_size += invalid_ipstr.len;
	    		}
	    		invalid_size = sizeof("invalid ips:") + invalid_size + ipstr_invalid_arr->nelts * sizeof(',') + sizeof("\r\n");
	    		b = ngx_create_temp_buf(r->pool,invalid_size);
	    		if(b == NULL){
	    			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,  "error happend when alloc memory(ngx_create_temp_buf)");
	    			goto GO_DONE;
	    		}
	    		u_char *invalid_buf = b->pos;//ngx_pcalloc(r->pool,invalid_size);
	    		u_char *invalid_buf_pos;
	    		invalid_buf_pos = ngx_sprintf(invalid_buf,"invalid ips:");
	    		for(loop=0;loop<ipstr_invalid_arr->nelts;loop++){
	    			ngx_str_t invalid_ipstr = value[loop];
	    			invalid_buf_pos = ngx_snprintf(invalid_buf_pos,invalid_ipstr.len,"%s",invalid_ipstr.data);
	    			invalid_buf_pos++;
	    			invalid_buf_pos = ngx_snprintf(invalid_buf_pos,1,",");
	    			invalid_buf_pos++;
	    		}
	    		invalid_buf_pos = ngx_snprintf(invalid_buf_pos,sizeof("\r\n"),"\r\n");

	    		b->last = invalid_buf_pos;
	    		b->last_buf = 1;
	}else{
	    		size_t size = sizeof("ok");
	    		b = ngx_create_temp_buf(r->pool,size);
	    		b->last = ngx_sprintf(b->last,"ok");
	    		b->last_buf = 1;
	}

	out->buf = b;
	out->next = NULL;
	r->headers_out.status = NGX_HTTP_OK;
	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only){
	    return;
	}
	ngx_http_output_filter(r, out);
	return;


GO_DONE:
	ngx_str_set(&r->headers_out.content_type,"text/plain");
	size_t size = sizeof("internal error:\r\n");
	b = ngx_create_temp_buf(r->pool,size);
	out = ngx_alloc_chain_link(r->pool);
	if(b == NULL || out == NULL){
		return ;
	}
	out->buf = b;
	out->next = NULL;
	b->last = ngx_sprintf(b->last,"internal error\r\n");
	b->last_buf = 1;
	r->headers_out.status = NGX_HTTP_SERVICE_UNAVAILABLE;
	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only){
		return;
	}
	ngx_http_output_filter(r, out);
	return;
}

static ngx_int_t
insert_into_dict(ngx_http_access_dynamic_ctx_t  *ctx, ngx_str_t ipaddr,ngx_cidr_t *cidr){
	ngx_http_access_dynamic_shctx_t *shm;
    shm = ctx->shm;
    ngx_uint_t key;
    key = ngx_hash_key_lc((u_char *)ipaddr.data, ipaddr.len) % DICT_CAPACITY;
    ngx_int_t idx = shm->bucket_idx[key];
    ngx_int_t last_used_bucket = shm->last_used_bucket;
    ngx_int_t pre_idx = idx;
    if (last_used_bucket >= DICT_BUCKET_CAPACITY - 1) {
        return -1;
    }
    if (idx >= 0) {
        while (idx >= 0 && ngx_strncasecmp((u_char *)&shm->bucket_arr[idx].addr_text, ipaddr.data,ipaddr.len)) {
            pre_idx = idx;
            idx = shm->bucket_arr[idx].next;
        }
        if (idx >= 0) {
            return -idx;
        } else {
        	ngx_cpystrn((u_char *)shm->bucket_arr[++last_used_bucket].addr_text, ipaddr.data,ipaddr.len);
        	shm->bucket_arr[last_used_bucket].addr = cidr->u.in.addr;
        	shm->bucket_arr[last_used_bucket].mask = cidr->u.in.mask;
            shm->bucket_arr[pre_idx].next = last_used_bucket;
        }
    } else {
        shm->bucket_idx[key] = ++last_used_bucket;
        ngx_cpystrn((u_char *)&shm->bucket_arr[last_used_bucket].addr_text, ipaddr.data,ipaddr.len);
        shm->bucket_arr[last_used_bucket].addr = cidr->u.in.addr;
        shm->bucket_arr[last_used_bucket].mask = cidr->u.in.mask;
    }
    shm->last_used_bucket = last_used_bucket;
    return last_used_bucket;
}

static ngx_int_t
search_from_dict(ngx_http_access_dynamic_ctx_t  *ctx, ngx_str_t *ipaddr){
	ngx_http_access_dynamic_shctx_t *shm;
    shm= ctx->shm;
    ngx_uint_t key;
    key = ngx_hash_key_lc((u_char *)ipaddr->data, ipaddr->len) % DICT_CAPACITY;
    ngx_int_t idx = shm->bucket_idx[key];
    if (idx >= 0) {
        while (idx >= 0 && ngx_strncasecmp((u_char *)&shm->bucket_arr[idx].addr_text, ipaddr->data,ipaddr->len)) {
            idx = shm->bucket_arr[idx].next;
        }
        if (idx >= 0) {
            return idx;
        } else {
            return -1;
        }
    } else {
        return -1;
    }
}

static char *
ngx_http_access_dynamic_exist_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	ngx_http_core_loc_conf_t  *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_access_dynamic_exist_handler;
	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_access_dynamic_exist_handler(ngx_http_request_t *r){
	ngx_int_t rc;
	ngx_str_t arg_ip_value;
	char *arg_ip_name = "ip=";
	char separator = '&';
	u_char *arg_ip_value_start,*arg_ip_value_end;
	ngx_http_access_dynamic_main_conf_t *main_conf;
	ngx_http_access_dynamic_ctx_t *ctx;

	if (!(r->method & (NGX_HTTP_GET)))	{
	    return NGX_HTTP_NOT_ALLOWED;
	}
	rc = ngx_http_discard_request_body(r);
	if (rc != NGX_OK)	{
	    return rc;
	}
	ngx_str_set(&r->headers_out.content_type,"text/plain");
	main_conf = ngx_http_get_module_main_conf(r,ngx_http_access_dynamic_module);
	ctx = (ngx_http_access_dynamic_ctx_t *)main_conf->shm_zone->data;
	arg_ip_value_start = ngx_strnstr((u_char *)r->args.data,arg_ip_name,r->args.len);
	arg_ip_value_start += sizeof("ip=");
	arg_ip_value_end = ngx_strlchr(arg_ip_value_start,r->args.data+r->args.len,separator);
	arg_ip_value.data = arg_ip_value_start;
	arg_ip_value.len = arg_ip_value_end - arg_ip_value_start;

	rc = search_from_dict(ctx,&arg_ip_value);

//	ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"lastid:%d",lastid);

	ngx_buf_t *b = ngx_create_temp_buf(r->pool,1);
	ngx_chain_t *out = ngx_alloc_chain_link(r->pool);
	if(b == NULL || out == NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	out->buf = b;
	out->next = NULL;
	if(rc>=0){
		b->last = ngx_sprintf(b->last,"1");
	}else{
		b->last = ngx_sprintf(b->last,"0");
	}
	b->last_buf = 1;
	r->headers_out.status = NGX_HTTP_OK;
	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only){
	    return rc;
	}

	return ngx_http_output_filter(r, out);
}

static char *
ngx_http_access_dynamic_del_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	ngx_http_core_loc_conf_t  *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_access_dynamic_del_handler;
	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_access_dynamic_del_handler(ngx_http_request_t *r){
	ngx_int_t rc;
	ngx_str_t arg_ip_value;
	char *arg_ip_name = "ip=";
	char separator = '&';
	u_char *arg_ip_value_start,*arg_ip_value_end;
	ngx_http_access_dynamic_main_conf_t *main_conf;
	ngx_http_access_dynamic_ctx_t *ctx;

	if (!(r->method & (NGX_HTTP_GET)))	{
	    return NGX_HTTP_NOT_ALLOWED;
	}
	rc = ngx_http_discard_request_body(r);
	if (rc != NGX_OK)	{
	    return rc;
	}
	ngx_str_set(&r->headers_out.content_type,"text/plain");
	main_conf = ngx_http_get_module_main_conf(r,ngx_http_access_dynamic_module);
	ctx = (ngx_http_access_dynamic_ctx_t *)main_conf->shm_zone->data;
	arg_ip_value_start = ngx_strnstr((u_char *)r->args.data,arg_ip_name,r->args.len);
	arg_ip_value_start += sizeof("ip=");
	arg_ip_value_end = ngx_strlchr(arg_ip_value_start,r->args.data+r->args.len,separator);
	arg_ip_value.data = arg_ip_value_start;
	arg_ip_value.len = arg_ip_value_end - arg_ip_value_start;

	rc = search_from_dict(ctx,&arg_ip_value);

//	ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"lastid:%d",lastid);

	ngx_buf_t *b = ngx_create_temp_buf(r->pool,1);
	ngx_chain_t *out = ngx_alloc_chain_link(r->pool);
	if(b == NULL || out == NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	out->buf = b;
	out->next = NULL;
	if(rc>=0){
		b->last = ngx_sprintf(b->last,"1");
	}else{
		b->last = ngx_sprintf(b->last,"0");
	}
	b->last_buf = 1;
	r->headers_out.status = NGX_HTTP_OK;
	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only){
	    return rc;
	}

	return ngx_http_output_filter(r, out);
}

static ngx_int_t
ngx_http_access_dynamic_init(ngx_conf_t *cf){
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_access_dynamic_handler;
    return NGX_OK;
}

static ngx_int_t
ngx_http_access_dynamic_handler(ngx_http_request_t *r){
	return 0;
}





