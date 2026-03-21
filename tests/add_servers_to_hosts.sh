sudo cp /etc/hosts "/etc/hosts.bak.$(date +%Y%m%d%H%M%S)" && \
    (
        sed -n '1,/^# SERVERS TEST HOSTS BEGIN/{/^# SERVERS TEST HOSTS BEGIN/!p;}' /etc/hosts; \
        echo "# SERVERS TEST HOSTS BEGIN"; \
        ./generate_servers.sh $1; \
        echo "# SERVERS TEST HOSTS END"; \
        sed -n '/^# SERVERS TEST HOSTS END/,${/^# SERVERS TEST HOSTS END/!p;}' /etc/hosts; \
    ) | \
    sudo tee /etc/hosts.new | \
    sed -n '/^# SERVERS TEST HOSTS BEGIN/,/^# SERVERS TEST HOSTS END/p' && \
        sudo mv /etc/hosts.new /etc/hosts

