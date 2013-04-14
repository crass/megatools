MAN1 = megadf megadl megaget megals megamkdir megaput megareg megarm megamv megastream megasync megafs
MAN5 = megarc
MAN7 = megatools

man1_MANS = $(addsuffix .1, $(MAN1))
man5_MANS = $(addsuffix .5, $(MAN5))
man7_MANS = $(addsuffix .7, $(MAN7))

BUILT_SOURCES = \
	$(addsuffix .1, $(MAN1)) \
	$(addsuffix .5, $(MAN5)) \
	$(addsuffix .7, $(MAN7))

EXTRA_DIST = \
	asciidoc.conf \
	footer.txt \
	remote-paths.txt \
	shared-options.txt \
	$(addsuffix .txt, $(MAN1) $(MAN5) $(MAN7)) \
	$(BUILT_SOURCES)

DISTCLEANFILES = $(BUILT_SOURCES)

%.1 %.5 %.7: %.txt shared-options.txt remote-paths.txt footer.txt asciidoc.conf
	a2x --asciidoc-opts="-f asciidoc.conf" -f manpage $<
	sed -i 's/\[FIXME: manual]/Megatools Manual/' $@
	sed -i 's/\[FIXME: source]/megatools $(VERSION)/' $@
