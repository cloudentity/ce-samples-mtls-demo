build:
	docker-compose build

run: 
	docker-compose up -d --no-build
	./scripts/wait.sh

run-all:
	./scripts/prep.sh
	docker-compose up --build -d 
	./scripts/wait.sh

stop:
	docker-compose down

.PHONY: clean
clean:
	docker-compose down -v --remove-orphans