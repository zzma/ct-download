curl -s https://www.gstatic.com/ct/log_list/log_list.json | jq '.logs[]| "{\"name\":\"\(.description)\",\"url\":\"https://\(.url)\",\"batch_size\":10000}"' | tr '[:upper:]' '[:lower:]' | tr ' ' '_' | sed "s/'//g" | sed 's,\\,,g' | sed 's/^"//g' | sed 's/"$//g' | sed 's=/","batch_size=","batch_size=g'
