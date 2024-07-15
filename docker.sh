#/bin/bash
case "$1" in
  "up")
    sudo docker compose up -d --build
    ;;
  "down")
    sudo docker compose down
    ;;
  "restart")
    sudo docker compose down && docker compose up -d --build
    ;;
  "attack")
    sudo docker exec -it seed-attacker bash
    ;;
  "term")
    sudo docker exec -it x-terminal-10.9.0.5 bash
    ;;
  "serv")
    sudo docker exec -it trusted-server-10.9.0.6 bash
    ;;
  *)
    echo "You have failed to specify what to do correctly."
    exit 1
    ;;
esac
