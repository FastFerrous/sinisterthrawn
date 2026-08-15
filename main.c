#include <stdio.h>
#include "tls.h"
#include "patch.h"

/* debug */
#include <unistd.h>
void print_config(const stamped_config_t *config)
{
    if (NULL == config)
    {
        return;
    }

    printf("key:         0x%02X\n", config->key);
    printf("mode:        %u (%s)\n", config->mode, config->mode == CALLBACK ? "CALLBACK" : "LISTEN");
    printf("sleep:       %u\n", config->sleep);
    printf("port:        %u\n", config->port);
    printf("interval:    %u\n", config->interval);
    printf("max_cb:      %u\n", config->max_cb);

    printf("spki:        ");
    for (uint64_t i = 0; i < config->spki.len; i++)
    {
        printf("%02X", config->spki.data[i]);
    }
    printf("\n");

    printf("address:     %.*s\n", (int)config->address.len, config->address.data);
    printf("sni:         %.*s\n", (int)config->sni.len, config->sni.data);

    printf("public_key:  %llu bytes\n", (unsigned long long)config->public_key.len);
    printf("private_key: %llu bytes\n", (unsigned long long)config->private_key.len);
}
/* end debug */

int main()
{
    /* extract embedded configuration to perform tls connection */
    stamped_config_t config = {0};
    if (!parse_config(&config))
    {
        printf("unable to extract config");
        return -1;
    }

    /* debug */
    print_config(&config);
    /* end debug */

    /* create temporary debug connection */
    tls_conn_t *cxt = tls_new(&config);
    if (NULL == cxt)
    {
        return 1;
    }

    // check mode, if connect, call connect and pass tls_conn into the function that handles the client connection
    // if server, go into listen and we wait here until we return.

    if (cxt->connect)
    {
        if (0 != cxt->connect(cxt, &config))
        {
            printf("failed to connect\n");
            return 1;
        }
        printf("connected to server\n");

        sleep(10);
    }

    if (cxt)
    {
        tls_destroy(&cxt);
    }

    return 0;
}

// main.c is purely debug really, will reorg once mtls has been built
// todo: create root build.sh that will eventually wrap the build_deps.sh and perform all in one go
// todo: work on mbedtls custom config, mbedtls/mbedtls_config.h, to reduce algos, etc.
