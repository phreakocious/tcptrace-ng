.PHONY: vendor-tcptrace vendor-clean test lint

VENDOR_DIR := vendor/tcptrace

vendor-tcptrace: $(VENDOR_DIR)/tcptrace ## Build the vendored tcptrace binary

$(VENDOR_DIR)/tcptrace: $(VENDOR_DIR)/Makefile
	$(MAKE) -C $(VENDOR_DIR) tcptrace

$(VENDOR_DIR)/Makefile: $(VENDOR_DIR)/configure
	cd $(VENDOR_DIR) && ./configure

$(VENDOR_DIR)/configure:
	@test -f $@ || (echo "submodule not initialized; run: git submodule update --init" && exit 1)

vendor-clean:
	-$(MAKE) -C $(VENDOR_DIR) clean
	rm -f $(VENDOR_DIR)/Makefile $(VENDOR_DIR)/config.log $(VENDOR_DIR)/config.status

test:
	pytest -q

lint:
	ruff check src tests
