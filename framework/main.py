from tls.tls import Tls

def main(): 
    tls = Tls()
    tls.listen()

if __name__ == "__main__":
    main()


# setup argparse, can be a listener or client, currently we will only build out server impl for now
# currently using the test certs, will be in arg parse, default to that location though. names must match svr_key, svr_cert, client_key, etc

# need to dump json recpt for passing as args. so a simple setup script thats interactive to build out json. 
# that json gets supplied into the main server 

# tls class needs locked behind our cmd class. we are a framework that creates sessions and we can handle multiple sessions