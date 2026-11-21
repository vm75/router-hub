# Sourced by root's .bashrc and the default Alpine login shell.
case $- in
    *i*)
        if [ "${ROUTER_LAB_BANNER_SHOWN:-0}" != 1 ]; then
            ROUTER_LAB_BANNER_SHOWN=1
            printf '\n'
            if [ -f /etc/router-lab/httpd-credentials.txt ]; then
                printf 'ASUS httpd Basic Auth: %s\n' "$(tr '\n' ' ' < /etc/router-lab/httpd-credentials.txt)"
            fi
            if [ -f /opt/etc/maestro/auth-token.txt ]; then
                printf 'Maestro API Token:  %s\n' "$(cat /opt/etc/maestro/auth-token.txt)"
            fi
            printf '\n%s\n' \
                'Access from host browser:' \
                '  Router Page: http://127.0.0.1:8080/user20.asp' \
                '  HTTPS Page:  https://127.0.0.1:8443/user20.asp (self-signed lab certificate)' \
                '  Direct API:  http://127.0.0.1:3030/api/version'
        fi
        ;;
esac
