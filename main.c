#include <stdio.h>
#include "tls.h"

#include <unistd.h> // sleep, debug

int main()
{
    tls_conn_t *cxt = tls_new();

    if (NULL == cxt)
    {
        return 1;
    }

    if (cxt->connect)
    {
        if (0 != cxt->connect(cxt, "127.0.0.1", "4443"))
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

// todo: need to develop the support for both listener and/or client modes. keep this in mind, most likely once connection is made, create custom session structure, that then gets supplied to a thread that performs tasking, etc.
// todo: hostname and address need to be different or should at least be able to be different as we connect to ip, but cert name is for cert, etc. (if not provided, match values)
// todo: work on poll to provide both static and dynamic arrays, currently only supports static
// todo: get client <-> server comms working -- then add taskings
// todo: create root build.sh that will eventually wrap the build_deps.sh and perform all in one go
// todo: work on mbedtls custom config, mbedtls/mbedtls_config.h, to reduce algos, etc.
// todo: when testing self signed, ensure cn is a valid name since that will be checked
