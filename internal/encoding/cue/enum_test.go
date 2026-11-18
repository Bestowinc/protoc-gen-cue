package cue

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"cuelang.org/go/cue"
	cueastutil "cuelang.org/go/cue/ast/astutil"
	"cuelang.org/go/cue/cuecontext"
	cueformat "cuelang.org/go/cue/format"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata")

const enumsProtoPath = "enums/v1/enums.proto"

func enumValue(name string, number int32) *descriptorpb.EnumValueDescriptorProto {
	return &descriptorpb.EnumValueDescriptorProto{Name: proto.String(name), Number: proto.Int32(number)}
}

// enumsFile covers the cases enum generation has to handle: a plain enum, a
// single-value enum, a two-value enum, an allow_alias enum and an enum nested
// in a message.
func enumsFile() *descriptorpb.FileDescriptorProto {
	return &descriptorpb.FileDescriptorProto{
		Name:    proto.String(enumsProtoPath),
		Package: proto.String("enums.v1"),
		Syntax:  proto.String("proto3"),
		Options: &descriptorpb.FileOptions{GoPackage: proto.String("example.com/enums/v1;enumsv1")},
		EnumType: []*descriptorpb.EnumDescriptorProto{
			{
				Name: proto.String("Color"),
				Value: []*descriptorpb.EnumValueDescriptorProto{
					enumValue("COLOR_UNSPECIFIED", 0),
					enumValue("COLOR_RED", 1),
					enumValue("COLOR_GREEN", 2),
					enumValue("COLOR_BLUE", 3),
				},
			},
			{
				Name:  proto.String("Single"),
				Value: []*descriptorpb.EnumValueDescriptorProto{enumValue("SINGLE_ONLY", 0)},
			},
			{
				Name: proto.String("Pair"),
				Value: []*descriptorpb.EnumValueDescriptorProto{
					enumValue("PAIR_ZERO", 0),
					enumValue("PAIR_ONE", 1),
				},
			},
			{
				Name:    proto.String("Status"),
				Options: &descriptorpb.EnumOptions{AllowAlias: proto.Bool(true)},
				Value: []*descriptorpb.EnumValueDescriptorProto{
					enumValue("STATUS_UNSPECIFIED", 0),
					enumValue("STATUS_STARTED", 1),
					enumValue("STATUS_RUNNING", 1),
					enumValue("STATUS_DONE", 2),
				},
			},
		},
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("Paint"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:     proto.String("color"),
						JsonName: proto.String("color"),
						Number:   proto.Int32(1),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_ENUM.Enum(),
						TypeName: proto.String(".enums.v1.Color"),
					},
					{
						Name:     proto.String("finish"),
						JsonName: proto.String("finish"),
						Number:   proto.Int32(2),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_ENUM.Enum(),
						TypeName: proto.String(".enums.v1.Paint.Finish"),
					},
				},
				EnumType: []*descriptorpb.EnumDescriptorProto{
					{
						Name: proto.String("Finish"),
						Value: []*descriptorpb.EnumValueDescriptorProto{
							enumValue("FINISH_UNSPECIFIED", 0),
							enumValue("FINISH_MATTE", 1),
							enumValue("FINISH_GLOSS", 2),
						},
					},
				},
			},
		},
	}
}

// generateEnums runs the generator over enumsFile with the given style and
// returns the formatted CUE source.
func generateEnums(t *testing.T, style EnumStyle) []byte {
	t.Helper()
	plugin, err := protogen.Options{}.New(&pluginpb.CodeGeneratorRequest{
		FileToGenerate: []string{enumsProtoPath},
		ProtoFile:      []*descriptorpb.FileDescriptorProto{enumsFile()},
	})
	if err != nil {
		t.Fatalf("protogen: %v", err)
	}
	g := NewGenerator()
	g.SetEnumStyle(style)
	for p, f := range plugin.FilesByPath {
		g.AddFile(p, f)
	}
	node, err := g.GenerateFile(context.Background(), enumsProtoPath)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := cueastutil.Sanitize(node); err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	b, err := cueformat.Node(node)
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	return b
}

func TestEnumGolden(t *testing.T) {
	for _, style := range []EnumStyle{EnumStyleDisjunction, EnumStyleRegex} {
		t.Run(string(style), func(t *testing.T) {
			got := generateEnums(t, style)
			golden := filepath.Join("testdata", "enums_"+string(style)+".golden.cue")
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read golden (run with -update to create it): %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("output differs from %s (run with -update to accept):\n--- got ---\n%s\n--- want ---\n%s", golden, got, want)
			}
		})
	}
}

// TestEnumStylesAgree checks that both styles accept and reject the same
// values and resolve to the same default.
func TestEnumStylesAgree(t *testing.T) {
	ctx := cuecontext.New()
	compile := func(style EnumStyle) cue.Value {
		v := ctx.CompileBytes(generateEnums(t, style))
		if err := v.Err(); err != nil {
			t.Fatalf("%s: compile: %v", style, err)
		}
		return v
	}
	disjunction, regex := compile(EnumStyleDisjunction), compile(EnumStyleRegex)

	valid := []string{
		"COLOR_UNSPECIFIED", "COLOR_RED", "COLOR_GREEN", "COLOR_BLUE",
		"SINGLE_ONLY", "PAIR_ZERO", "PAIR_ONE",
		"STATUS_UNSPECIFIED", "STATUS_STARTED", "STATUS_RUNNING", "STATUS_DONE",
		"FINISH_UNSPECIFIED", "FINISH_MATTE", "FINISH_GLOSS",
	}
	// Rejected by every enum, including values that would match a regex
	// without its anchors or grouping.
	invalid := []string{"", "NOPE", "COLOR_REDX", "XCOLOR_RED", "COLOR_RED|COLOR_BLUE", "COLOR_.*"}
	inputs := append(append([]string{}, valid...), invalid...)
	defs := []string{"#Color", "#Single", "#Pair", "#Status", "#Paint_Finish"}

	for _, def := range defs {
		path := cue.ParsePath(def)
		d, r := disjunction.LookupPath(path), regex.LookupPath(path)
		if !d.Exists() || !r.Exists() {
			t.Fatalf("%s: missing definition (disjunction=%v regex=%v)", def, d.Exists(), r.Exists())
		}

		dDef, dOK := d.Default()
		rDef, rOK := r.Default()
		dStr, _ := dDef.String()
		rStr, _ := rDef.String()
		if dOK != rOK || dStr != rStr {
			t.Errorf("%s: default: disjunction=(%q, %v) regex=(%q, %v)", def, dStr, dOK, rStr, rOK)
		}

		for _, in := range inputs {
			dErr := d.Unify(ctx.CompileString(strconv.Quote(in))).Validate(cue.Concrete(true))
			rErr := r.Unify(ctx.CompileString(strconv.Quote(in))).Validate(cue.Concrete(true))
			if (dErr == nil) != (rErr == nil) {
				t.Errorf("%s & %q: disjunction err=%v, regex err=%v", def, in, dErr, rErr)
			}
		}
		for _, in := range invalid {
			if r.Unify(ctx.CompileString(strconv.Quote(in))).Validate(cue.Concrete(true)) == nil {
				t.Errorf("%s & %q: regex style accepted an invalid value", def, in)
			}
		}
	}
}

func TestParseEnumStyle(t *testing.T) {
	for in, want := range map[string]EnumStyle{
		"":            EnumStyleDisjunction,
		"disjunction": EnumStyleDisjunction,
		"regex":       EnumStyleRegex,
	} {
		got, err := ParseEnumStyle(in)
		if err != nil || got != want {
			t.Errorf("ParseEnumStyle(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseEnumStyle("bogus"); err == nil {
		t.Error("ParseEnumStyle(\"bogus\"): want error")
	}
}
