build:
	docker-compose build

run: 
	docker-compose up -d --no-build
	./scripts/wait.sh

run-all:
	docker-compose up --build -d 
	npm start

stop:
	docker-compose down

.PHONY: clean
clean:
	docker-compose down -v --remove-orphans