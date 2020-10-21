curl -s https://valid.apple.com/ct/log_list/current_log_list.json | jq '.operators[].logs[]| "{\"name\":\"\(.description)\",\"url\":\"\(.url)\",\"state\":\"\(.state)\",\"batch_size\":10000}"' | tr '[:upper:]' '[:lower:]' | tr ' ' '_' | sed "s/'//g" | sed 's,\\,,g' | sed 's/^"//g' | sed 's/"$//g' | egrep -v "rejected|pending"
