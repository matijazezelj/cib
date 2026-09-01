.PHONY: up down restart logs build clean scan-now

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

build:
	docker compose build --no-cache

logs:
	docker compose logs -f

scan-now:
	docker exec cib-checker python /app/checker.py --once

clean:
	docker compose down -v
	docker rmi cib-cib-checker 2>/dev/null || true
