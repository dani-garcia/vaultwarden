OBJECTS := $(shell find ./ -mindepth 2 -name 'Dockerfile*')

all: $(OBJECTS)

%/Dockerfile: Dockerfile.j2 render_template
	./render_template "$<" "{\"target_file\":\"$@\"}" > "$@"

%/Dockerfile.alpine: Dockerfile.j2 render_template
	./render_template "$<" "{\"target_file\":\"$@\"}" > "$@"

%/Dockerfile.buildkit: Dockerfile.j2 render_template
	./render_template "$<" "{\"target_file\":\"$@\"}" > "$@"

%/Dockerfile.buildkit.alpine: Dockerfile.j2 render_template
	./render_template "$<" "{\"target_file\":\"$@\"}" > "$@"
