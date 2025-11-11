/*
Copyright Arata Furukawa

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cue

import (
	"context"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"cuelang.org/go/cue/ast"
	"cuelang.org/go/cue/parser"
	"cuelang.org/go/cue/token"
	"github.com/Bestowinc/protoc-gen-cue/pkg/options"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type generateFileContextKey struct{}

var escape *regexp.Regexp

func init() {
	escape = regexp.MustCompile(`[^a-zA-Z0-9_]`)
}

func escapeName[T ~string](s T) string {
	return string(escape.ReplaceAll([]byte(s), []byte("_")))
}

func safeLabel(s string) ast.Label {
	tok := token.Lookup(s)
	switch tok {
	case token.IDENT:
		return &ast.Ident{
			Name: s,
		}
	default:
		return &ast.BasicLit{
			Kind:  token.STRING,
			Value: strconv.Quote(s),
		}
	}
}

// For debug purpose.
func printf(f string, args ...any) {
	fmt.Fprintf(os.Stderr, f, args...)
}

// getCueImportPath returns the CUE import path for a file.
// It first checks for a cue_package file option (defined in proto/core/options.proto),
// falling back to the Go import path if not present.
func getCueImportPath(file *protogen.File) CueImportPath {
	// Try to get the cue_package option
	fileOpts := file.Proto.GetOptions()

	if fileOpts == nil {
		return ""
	}

	ext := proto.GetExtension(fileOpts, options.E_CuePackage)

	if ext == nil {
		return ""
	}

	if cuePackage, ok := ext.(string); ok && cuePackage != "" {
		return CueImportPath(cuePackage)
	}

	return ""
}

type Generator struct {
	imports    map[protogen.GoImportPath]*ast.ImportSpec
	deps       map[protogen.GoImportPath]*protogen.File
	cueImports map[protogen.GoImportPath]CueImportPath // maps GoImportPath to CueImportPath
	files      map[string]*protogen.File
	lets       map[string]*ast.LetClause
}

func NewGenerator() *Generator {
	return &Generator{
		imports:    map[protogen.GoImportPath]*ast.ImportSpec{},
		deps:       map[protogen.GoImportPath]*protogen.File{},
		cueImports: map[protogen.GoImportPath]CueImportPath{},
		files:      map[string]*protogen.File{},
		lets:       map[string]*ast.LetClause{},
	}
}

func (g *Generator) AddFile(p string, f *protogen.File) {
	g.files[p] = f
	g.deps[f.GoImportPath] = f
	if _, ok := g.cueImports[f.GoImportPath]; !ok {
		if cueImportPath := getCueImportPath(f); cueImportPath != "" {
			g.cueImports[f.GoImportPath] = cueImportPath
		}
	}
}

func (g *Generator) UseBuiltinType(ctx context.Context, name string) ast.Expr {
	return &ast.Ident{
		Name: name,
	}
}

func (g *Generator) Import(ctx context.Context, p protogen.GoImportPath, alias, name string, resolve bool) (ast.Expr, error) {
	if resolve {
		_, resolved := g.deps[p]
		if !resolved {
			return nil, fmt.Errorf("unable to resolve: %s.#%s", string(p), name)
		}
	}
	fileVal := ctx.Value(generateFileContextKey{})
	if fileVal == nil {
		panic(fmt.Errorf("current generate file is unknown"))
	}
	file, ok := fileVal.(*protogen.File)
	if !ok {
		panic(fmt.Errorf("current generate file is unknown"))
	}
	if p == file.GoImportPath {
		return &ast.Ident{
			Name: name,
		}, nil
	}
	spec, ok := g.imports[p]
	if ok {
		return &ast.SelectorExpr{
			X: &ast.Ident{
				Name: spec.Name.Name,
			},
			Sel: &ast.Ident{
				Name: name,
			},
		}, nil
	}

	quotedImportPath := p.String()
	importPath := string(p)

	if cuePath, ok := g.cueImports[p]; ok && cuePath != "" {
		quotedImportPath = cuePath.String()
		importPath = string(cuePath)
	}

	spec = &ast.ImportSpec{
		Path: &ast.BasicLit{
			Kind:     token.STRING,
			Value:    quotedImportPath,
			ValuePos: token.Blank.Pos(),
		},
		EndPos: token.Newline.Pos(),
	}
	if alias == "" {
		spec.Name = &ast.Ident{
			NamePos: token.Newline.Pos(),
			Name:    escapeName(importPath) + "__",
		}
	} else {
		spec.Name = &ast.Ident{
			NamePos: token.Newline.Pos(),
			Name:    alias + "__",
		}
	}
	g.imports[p] = spec
	return &ast.SelectorExpr{
		X: &ast.Ident{
			Name: spec.Name.Name,
		},
		Sel: &ast.Ident{
			Name: name,
		},
	}, nil
}

func (g *Generator) ResolveGoType(ctx context.Context, ident protogen.GoIdent) (ast.Expr, error) {
	return g.Import(ctx, ident.GoImportPath, "", "#"+ident.GoName, true)
}

// getCuePackageName determines the appropriate CUE package name for a proto file
func (g *Generator) getCuePackageName(protoPath string, file *protogen.File) string {
	// Use the directory name that the proto file is in
	dir := path.Dir(protoPath)
	if dir == "." || dir == "" {
		return string(file.GoPackageName)
	}

	// Get the last part of the directory path
	parts := strings.Split(dir, "/")
	if len(parts) > 0 {
		dirName := parts[len(parts)-1]
		// Ensure it's a valid CUE identifier
		if dirName != "" && !strings.ContainsAny(dirName, ".-") {
			return dirName
		}
	}

	// Fallback to "main" if we can't determine a good name
	return string(file.GoPackageName)
}

func (g *Generator) GenerateFile(ctx context.Context, p string) (*ast.File, error) {
	file := g.files[p]
	ctx = context.WithValue(ctx, generateFileContextKey{}, file)

	// Reset per-file state
	// The generator is reused across multiple files, so we need to clear imports
	// that were collected from previous file generations
	g.imports = map[protogen.GoImportPath]*ast.ImportSpec{}
	g.lets = map[string]*ast.LetClause{}

	// Set the CUE package name
	pkg := &ast.Package{
		Name: &ast.Ident{
			Name: g.getCuePackageName(p, file),
		},
	}
	pkgAttr := &ast.Attribute{
		Text: fmt.Sprintf("@protobuf(%s,syntax=%s)", file.Desc.Package(), *file.Proto.Syntax),
	}
	rootDecls := []ast.Decl{}
	fields, err := g.fromEnums(ctx, file)
	if err != nil {
		return nil, fmt.Errorf("enums: %w", err)
	}
	for _, field := range fields {
		rootDecls = append(rootDecls, field)
	}
	fields, err = g.fromMessages(ctx, file)
	if err != nil {
		return nil, fmt.Errorf("messages: %w", err)
	}
	for _, field := range fields {
		rootDecls = append(rootDecls, field)
	}
	var importSpecs []*ast.ImportSpec
	for _, i := range g.imports {
		importSpecs = append(importSpecs, i)
	}
	if len(importSpecs) == 1 {
		importSpecs[0].Name.NamePos = token.Blank.Pos()
		importSpecs[0].Path.ValuePos = token.Blank.Pos()
	}
	headDecls := []ast.Decl{pkg, pkgAttr}

	// Add import declaration if there are any imports
	// The formatter needs this in Decls to know where to place imports
	if len(importSpecs) > 0 {
		importsDecl := &ast.ImportDecl{
			Specs: importSpecs,
		}
		headDecls = append(headDecls, importsDecl)
	}

	for _, let := range g.lets {
		headDecls = append(headDecls, let)
	}
	rootDecls = append(headDecls, rootDecls...)

	// Only set Imports field if there are actual imports
	// Setting it to an empty slice causes the formatter to render "import ()"
	var imports []*ast.ImportSpec
	if len(importSpecs) > 0 {
		imports = importSpecs
	}

	root := ast.File{
		Filename:   file.GeneratedFilenamePrefix + "_gen.cue",
		Decls:      rootDecls,
		Imports:    imports,
		Unresolved: []*ast.Ident{},
	}
	return &root, nil
}

func (g *Generator) fromEnums(ctx context.Context, file *protogen.File) ([]*ast.Field, error) {
	enums := file.Enums
	var flatten func([]*protogen.Message)
	flatten = func(msgs []*protogen.Message) {
		for _, m := range msgs {
			enums = append(enums, m.Enums...)
			flatten(m.Messages)
		}
	}
	flatten(file.Messages)
	var fields []*ast.Field
	for _, e := range enums {
		field, err := g.enumAsDef(ctx, e)
		if err != nil {
			return nil, fmt.Errorf("enum: %s: %w", e.GoIdent.GoName, err)
		}
		fields = append(fields, field)
		for _, ev := range e.Values {
			field, err = g.enumValueAsDef(ctx, ev)
			if err != nil {
				return nil, fmt.Errorf("enum value: %s of %s: %w", ev.Desc.Name(), e.Desc.Name(), err)
			}
			fields = append(fields, field)
		}
	}
	return fields, nil
}

func (g *Generator) fromMessages(ctx context.Context, file *protogen.File) ([]*ast.Field, error) {
	var messages []*protogen.Message
	var flatten func([]*protogen.Message)
	flatten = func(msgs []*protogen.Message) {
		for _, m := range msgs {
			messages = append(messages, m)
			flatten(m.Messages)
		}
	}
	var fields []*ast.Field
	flatten(file.Messages)
	for _, m := range messages {
		field, err := g.messageAsDef(ctx, m)
		if err != nil {
			return nil, fmt.Errorf("message: %s: %w", m.Desc.Name(), err)
		}
		fields = append(fields, field)
	}
	return fields, nil
}

func (g *Generator) enumValueAsDef(ctx context.Context, ev *protogen.EnumValue) (*ast.Field, error) {
	field := &ast.Field{
		Label: &ast.Ident{
			NamePos: token.Newline.Pos(),
			Name:    "#" + ev.GoIdent.GoName,
		},
		Optional: token.NoPos,
		Value: &ast.BasicLit{
			Kind:  token.STRING,
			Value: fmt.Sprintf("%q", ev.Desc.Name()),
		},
		// Value: &ast.BasicLit{
		// 	Kind:  token.INT,
		// 	Value: fmt.Sprintf("%d", ev.Desc.Number()),
		// },
		Attrs: []*ast.Attribute{},
	}
	for _, c := range ev.Comments.LeadingDetached {
		if cg := toLeadingComments(c); cg != nil {
			field.AddComment(cg)
		}
	}
	if cg := toLeadingComments(ev.Comments.Leading); cg != nil {
		field.AddComment(cg)
	}
	if len(field.Comments()) == 0 {
		field.Label = &ast.Ident{
			NamePos: token.NewSection.Pos(),
			Name:    "#" + ev.GoIdent.GoName,
		}
	}
	if cg := toTrailingComments(ev.Comments.Trailing); cg != nil {
		cg.Position = 4 + int8(len(field.Attrs))
		field.AddComment(cg)
	}
	return field, nil
}

func (g *Generator) enumAsDef(ctx context.Context, e *protogen.Enum) (*ast.Field, error) {
	field := &ast.Field{
		Label: &ast.Ident{
			NamePos: token.Newline.Pos(),
			Name:    "#" + e.GoIdent.GoName,
		},
		Optional: token.NoPos,
		Attrs:    []*ast.Attribute{},
	}
	for _, enumItem := range e.Values {
		var value ast.Expr
		value = &ast.BasicLit{
			Kind:  token.STRING,
			Value: "#" + enumItem.GoIdent.GoName,
		}
		if len(e.Values) > 1 && enumItem.Desc.Number() == 0 {
			value = &ast.UnaryExpr{
				Op: token.MUL,
				X:  value,
			}
		}
		if field.Value == nil {
			field.Value = value
			continue
		}
		field.Value = &ast.BinaryExpr{
			X:  field.Value,
			Op: token.OR,
			Y:  value,
		}
	}
	for _, c := range e.Comments.LeadingDetached {
		if cg := toLeadingComments(c); cg != nil {
			field.AddComment(cg)
		}
	}
	if cg := toLeadingComments(e.Comments.Leading); cg != nil {
		field.AddComment(cg)
	}
	if len(field.Comments()) == 0 {
		field.Label = &ast.Ident{
			NamePos: token.NewSection.Pos(),
			Name:    "#" + e.GoIdent.GoName,
		}
	}
	if cg := toTrailingComments(e.Comments.Trailing); cg != nil {
		cg.Position = 4 + int8(len(field.Attrs))
		field.AddComment(cg)
	}
	return field, nil
}

func (g *Generator) oneofAsField(ctx context.Context, e *protogen.Oneof) (*ast.Field, error) {
	field := &ast.Field{
		Label: &ast.Ident{
			NamePos: token.Newline.Pos(),
			Name:    "_oneof_" + string(e.Desc.Name()),
		},
		// Value: &ast.UnaryExpr{
		// 	Op: token.MUL,
		// 	X: &ast.BasicLit{
		// 		Kind:  token.NULL,
		// 		Value: "null",
		// 	},
		// },
		Optional: token.NoPos,
		Attrs:    []*ast.Attribute{},
	}
	for _, which := range e.Fields {
		id := &ast.BasicLit{
			Kind:  token.IDENT,
			Value: which.Desc.JSONName(),
		}
		if field.Value == nil {
			field.Value = id
			continue
		}
		field.Value = &ast.BinaryExpr{
			X:  field.Value,
			Op: token.AND,
			Y:  id,
		}
	}
	for _, c := range e.Comments.LeadingDetached {
		if cg := toLeadingComments(c); cg != nil {
			field.AddComment(cg)
		}
	}
	if cg := toLeadingComments(e.Comments.Leading); cg != nil {
		field.AddComment(cg)
	}
	if len(field.Comments()) == 0 {
		field.Label = &ast.Ident{
			NamePos: token.NewSection.Pos(),
			Name:    "_oneof_" + string(e.Desc.Name()),
		}
	}
	if cg := toTrailingComments(e.Comments.Trailing); cg != nil {
		cg.Position = 4 + int8(len(field.Attrs))
		field.AddComment(cg)
	}
	return field, nil
}

func (g *Generator) messageAsDef(ctx context.Context, m *protogen.Message) (*ast.Field, error) {
	s := &ast.StructLit{}
	cueStruct := &ast.Field{
		Label: &ast.Ident{
			Name: "#" + m.GoIdent.GoName,
		},
		Optional: token.NoPos,
		Value:    s,
		Attrs:    []*ast.Attribute{},
	}
	for _, c := range m.Comments.LeadingDetached {
		if cg := toLeadingComments(c); cg != nil {
			cueStruct.AddComment(cg)
		}
	}
	if cg := toLeadingComments(m.Comments.Leading); cg != nil {
		cueStruct.AddComment(cg)
	}
	if len(cueStruct.Comments()) == 0 {
		cueStruct.Label = &ast.Ident{
			NamePos: token.NewSection.Pos(),
			Name:    "#" + m.GoIdent.GoName,
		}
	}
	if cg := toTrailingComments(m.Comments.Trailing); cg != nil {
		s.Elts = append(s.Elts, cg)
	}
	s.Elts = append(s.Elts, &ast.Attribute{
		At:   token.NewSection.Pos(),
		Text: "@protobuf(" + string(m.Desc.FullName()) + ")",
	})
	for _, oneof := range m.Oneofs {
		field, err := g.oneofAsField(ctx, oneof)
		if err != nil {
			return nil, fmt.Errorf("oneof: %s of %s: %w", oneof.Desc.Name(), m.Desc.Name(), err)
		}
		s.Elts = append(s.Elts, field)
	}
	for _, f := range m.Fields {
		fields, err := g.fieldAsFields(ctx, f)
		if err != nil {
			return nil, fmt.Errorf("field: %s of %s: %w", f.Desc.Name(), m.Desc.Name(), err)
		}
		for _, cueField := range fields {
			s.Elts = append(s.Elts, cueField)
		}
	}
	return cueStruct, nil
}

func (g *Generator) fieldAsField(ctx context.Context, f *protogen.Field) (*ast.Field, error) {
	attrs := []*ast.Attribute{
		{Text: "@go(" + f.GoName + ")"},
		{Text: fmt.Sprintf("@protobuf(%d,name=%s)", f.Desc.Number(), f.Desc.Name())},
		// {Text: fmt.Sprintf("@debug(%s,%d,%d,%v)", f.Desc.Kind().GoString(), f.Desc.Cardinality(), f.Desc.Index(), f.Desc.IsList())},
	}
	cueField := &ast.Field{
		Label:    safeLabel(f.Desc.JSONName()),
		Optional: token.NoPos,
		Attrs:    attrs,
	}

	if f.Desc.HasOptionalKeyword() {
		cueField.Optional = token.Blank.Pos()
	}
	if oneof := f.Desc.ContainingOneof(); oneof != nil {
		cueField.Optional = token.Blank.Pos()
	}
	switch f.Desc.Kind() {
	case protoreflect.MessageKind:
		if f.Desc.IsMap() {
			// TODO warning
			// key := f.Desc.MapKey()
			// if key.Kind() != protoreflect.StringKind {
			// 	panic(fmt.Errorf("map key supports only string: got %s", key.Kind().GoString()))
			// }
			var value *protogen.Field
			for _, f := range f.Message.Fields {
				if f.GoName == "Value" {
					value = f
				}
			}
			if value == nil {
				return nil, fmt.Errorf("value field not found")
			}
			mapValueField, err := g.fieldAsField(ctx, value)
			if err != nil {
				return nil, fmt.Errorf("resolve map value: %w", err)
			}
			mapField := &ast.Field{
				Label: &ast.ListLit{
					Elts: []ast.Expr{
						&ast.Ident{Name: "_"},
					},
				},
				Value: mapValueField.Value,
			}
			cueField.Value = &ast.StructLit{
				Elts: []ast.Decl{mapField},
			}
			break
		}
		if field, err := g.wellKnownTypeMessage(ctx, f.Message); err != nil {
			return nil, fmt.Errorf("well known type message: %s: %w", f.Desc.Name(), err)
		} else if field != nil {
			cueField.Value = field
			break
		}
		resolved, err := g.ResolveGoType(ctx, f.Message.GoIdent)
		if err != nil {
			return nil, fmt.Errorf("resolve: %w", err)
		}
		cueField.Value = resolved
	case protoreflect.EnumKind:
		if field, ok, err := g.wellKnownTypeEnum(ctx, f.Enum); err != nil {
			return nil, fmt.Errorf("well known type enum: %s: %w", f.Desc.Name(), err)
		} else if ok {
			cueField.Value = field
			break
		}
		resolved, err := g.ResolveGoType(ctx, f.Enum.GoIdent)
		if err != nil {
			return nil, fmt.Errorf("resolve: %w", err)
		}
		cueField.Value = resolved
	case protoreflect.BoolKind:
		cueField.Value = g.UseBuiltinType(ctx, "bool")
	case protoreflect.StringKind:
		cueField.Value = g.UseBuiltinType(ctx, "string")
	case protoreflect.BytesKind:
		cueField.Value = g.UseBuiltinType(ctx, "bytes")
	case protoreflect.Int32Kind, protoreflect.Fixed32Kind:
		cueField.Value = g.UseBuiltinType(ctx, "int32")
	case protoreflect.Uint32Kind:
		cueField.Value = g.UseBuiltinType(ctx, "uint32")
	case protoreflect.Int64Kind, protoreflect.Fixed64Kind:
		cueField.Value = g.UseBuiltinType(ctx, "int64")
	case protoreflect.Uint64Kind:
		cueField.Value = g.UseBuiltinType(ctx, "uint64")
	case protoreflect.FloatKind:
		cueField.Value = g.UseBuiltinType(ctx, "float32")
	case protoreflect.DoubleKind:
		cueField.Value = g.UseBuiltinType(ctx, "float64")
	default:
		// TODO error
		return nil, fmt.Errorf("unknown kind: %s of %s", f.Desc.Kind().GoString(), f.Desc.Name())
	}
	if f.Desc.IsList() {
		cueField.Value = &ast.ListLit{
			Elts: []ast.Expr{
				&ast.Ellipsis{
					Type: cueField.Value,
				},
			},
		}
	}
	for _, c := range f.Comments.LeadingDetached {
		if cg := toLeadingComments(c); cg != nil {
			cueField.AddComment(cg)
		}
	}
	if cg := toLeadingComments(f.Comments.Leading); cg != nil {
		cueField.AddComment(cg)
	}
	if cg := toTrailingComments(f.Comments.Trailing); cg != nil {
		cg.Position = 4 + int8(len(cueField.Attrs))
		cueField.AddComment(cg)
	}
	return cueField, nil
}

func (g *Generator) fieldAsFields(ctx context.Context, f *protogen.Field) ([]*ast.Field, error) {
	var opt *options.FieldOptions
	opts := f.Desc.Options()
	ext := proto.GetExtension(opts, options.E_Field)
	if ext != nil {
		opt = ext.(*options.FieldOptions)
	}
	var cueFields []*ast.Field
	cueField, err := g.fieldAsField(ctx, f)
	if err != nil {
		return nil, err
	}

	// Handle default field option
	if opt != nil && opt.Default != "" {
		// Parse the default value to create the appropriate CUE expression
		defaultExpr, err := parser.ParseExpr("", opt.Default, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("failed to parse default value %q for field %s: %w", opt.Default, f.Desc.Name(), err)
		}

		// Create a binary expression: *defaultValue | type
		cueField.Value = &ast.BinaryExpr{
			X:  defaultExpr, // The default value (e.g., *true, *false, etc.)
			Op: token.OR,
			Y:  cueField.Value, // The original type (e.g., bool, string, etc.)
		}
	}

	cueFields = append(cueFields, cueField)
	if opt != nil && opt.Expr != "" {
		valExpr, err := parser.ParseExpr("", opt.Expr, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("failed to parse expression %q for field %s: %w", opt.Expr, f.Desc.Name(), err)
		}
		cueValField := &ast.Field{
			Label:    safeLabel(f.Desc.JSONName()),
			Optional: token.NoPos,
			Value:    valExpr,
			Attrs:    []*ast.Attribute{},
		}
		cueFields = append(cueFields, cueValField)
	}
	return cueFields, nil
}
