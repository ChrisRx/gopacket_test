.PHONY: build

target=nozzle

build:
	@echo -n "Building stuff ..."
	@go build -o $(target)
	@echo "Done"

clean:
	@echo "Cleaning ..."
	rm $(target)
