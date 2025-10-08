# dii-export-monitors

This Python script exports monitors from NetApp Data Infrastructure Insights (DII) into an excel file.

    usage: dii-export-monitors.py [-h] -u URL -t TOKEN [-px PROXY] [-pxu PROXY_USER] [-pxp PROXY_PASSWD] [-ll {DEBUG,INFO,WARNING,ERROR,CRITICAL}]

    * Export monitors from NetApp Data Infrastructure Insights (DII).

    options:  
        -h, --help                  show this help message and exit  
        -u URL, --url URL           URL to DII Tenant: https://dii_tenant.cloudinsights.netapp.com (default: None)  
        -t TOKEN, --token TOKEN     Token file containing the actual token for the DII Tenant (default: None)
        -px PROXY, --proxy PROXY    Proxy for http(s) connections to Tenant: proxy.yourdomain.com:3128 (default: None)
        -pxu PROXY_USER, --proxy-user PROXY_USER
                                    User to authenticate with at proxy. (default: None)
        -pxp PROXY_PASSWD, --proxy-passwd PROXY_PASSWD
                                    Password to authenticate with at proxy. (default: None)
        -ll {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                                    Loglevel for console output (default: INFO)

The genareted excel file will be put in the directory from where the script has been executed.