.PHONY: up down logs rebuild

up:
	docker compose up --build

down:
	docker compose down

logs:
	docker compose logs -f

rebuild:
	docker compose down
	docker compose build --no-cache
	docker compose up
