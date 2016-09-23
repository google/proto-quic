// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package com.google.javascript.jscomp;

import com.google.javascript.jscomp.NodeTraversal.AbstractPostOrderCallback;
import com.google.javascript.rhino.IR;
import com.google.javascript.rhino.JSDocInfoBuilder;
import com.google.javascript.rhino.JSTypeExpression;
import com.google.javascript.rhino.Node;
import com.google.javascript.rhino.Token;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Compiler pass for Chrome-specific needs. It handles the following Chrome JS features:
 * <ul>
 * <li>namespace declaration using {@code cr.define()},
 * <li>unquoted property declaration using {@code {cr|Object}.defineProperty()}.
 * </ul>
 *
 * <p>For the details, see tests inside ChromePassTest.java.
 */
public class ChromePass extends AbstractPostOrderCallback implements CompilerPass {
    final AbstractCompiler compiler;

    private Set<String> createdObjects;

    private static final String CR_DEFINE = "cr.define";
    private static final String CR_EXPORT_PATH = "cr.exportPath";
    private static final String OBJECT_DEFINE_PROPERTY = "Object.defineProperty";
    private static final String CR_DEFINE_PROPERTY = "cr.defineProperty";
    private static final String CR_MAKE_PUBLIC = "cr.makePublic";

    private static final String CR_DEFINE_COMMON_EXPLANATION = "It should be called like this:"
            + " cr.define('name.space', function() '{ ... return {Export: Internal}; }');";

    static final DiagnosticType CR_DEFINE_WRONG_NUMBER_OF_ARGUMENTS =
            DiagnosticType.error("JSC_CR_DEFINE_WRONG_NUMBER_OF_ARGUMENTS",
                    "cr.define() should have exactly 2 arguments. " + CR_DEFINE_COMMON_EXPLANATION);

    static final DiagnosticType CR_EXPORT_PATH_TOO_FEW_ARGUMENTS =
            DiagnosticType.error("JSC_CR_EXPORT_PATH_TOO_FEW_ARGUMENTS",
                    "cr.exportPath() should have at least 1 argument: path name.");

    static final DiagnosticType CR_DEFINE_INVALID_FIRST_ARGUMENT =
            DiagnosticType.error("JSC_CR_DEFINE_INVALID_FIRST_ARGUMENT",
                    "Invalid first argument for cr.define(). " + CR_DEFINE_COMMON_EXPLANATION);

    static final DiagnosticType CR_DEFINE_INVALID_SECOND_ARGUMENT =
            DiagnosticType.error("JSC_CR_DEFINE_INVALID_SECOND_ARGUMENT",
                    "Invalid second argument for cr.define(). " + CR_DEFINE_COMMON_EXPLANATION);

    static final DiagnosticType CR_DEFINE_INVALID_RETURN_IN_FUNCTION =
            DiagnosticType.error("JSC_CR_DEFINE_INVALID_RETURN_IN_SECOND_ARGUMENT",
                    "Function passed as second argument of cr.define() should return the"
                    + " dictionary in its last statement. " + CR_DEFINE_COMMON_EXPLANATION);

    static final DiagnosticType CR_DEFINE_PROPERTY_INVALID_PROPERTY_KIND =
            DiagnosticType.error("JSC_CR_DEFINE_PROPERTY_INVALID_PROPERTY_KIND",
                    "Invalid cr.PropertyKind passed to cr.defineProperty(): expected ATTR,"
                    + " BOOL_ATTR or JS, found \"{0}\".");

    static final DiagnosticType CR_MAKE_PUBLIC_HAS_NO_JSDOC =
            DiagnosticType.error("JSC_CR_MAKE_PUBLIC_HAS_NO_JSDOC",
                    "Private method exported by cr.makePublic() has no JSDoc.");

    static final DiagnosticType CR_MAKE_PUBLIC_MISSED_DECLARATION =
            DiagnosticType.error("JSC_CR_MAKE_PUBLIC_MISSED_DECLARATION",
                    "Method \"{1}_\" exported by cr.makePublic() on \"{0}\" has no declaration.");

    static final DiagnosticType CR_MAKE_PUBLIC_INVALID_SECOND_ARGUMENT =
            DiagnosticType.error("JSC_CR_MAKE_PUBLIC_INVALID_SECOND_ARGUMENT",
                    "Invalid second argument passed to cr.makePublic(): should be array of " +
                    "strings.");

    public ChromePass(AbstractCompiler compiler) {
        this.compiler = compiler;
        // The global variable "cr" is declared in ui/webui/resources/js/cr.js.
        this.createdObjects = new HashSet<>(Arrays.asList("cr"));
    }

    @Override
    public void process(Node externs, Node root) {
        NodeTraversal.traverse(compiler, root, this);
    }

    @Override
    public void visit(NodeTraversal t, Node node, Node parent) {
        if (node.isCall()) {
            Node callee = node.getFirstChild();
            if (callee.matchesQualifiedName(CR_DEFINE)) {
                visitNamespaceDefinition(node, parent);
                compiler.reportCodeChange();
            } else if (callee.matchesQualifiedName(CR_EXPORT_PATH)) {
                visitExportPath(node, parent);
                compiler.reportCodeChange();
            } else if (callee.matchesQualifiedName(OBJECT_DEFINE_PROPERTY) ||
                    callee.matchesQualifiedName(CR_DEFINE_PROPERTY)) {
                visitPropertyDefinition(node, parent);
                compiler.reportCodeChange();
            } else if (callee.matchesQualifiedName(CR_MAKE_PUBLIC)) {
                if (visitMakePublic(node, parent)) {
                    compiler.reportCodeChange();
                }
            }
        }
    }

    private void visitPropertyDefinition(Node call, Node parent) {
        Node callee = call.getFirstChild();
        String target = call.getChildAtIndex(1).getQualifiedName();
        if (callee.matchesQualifiedName(CR_DEFINE_PROPERTY) && !target.endsWith(".prototype")) {
            target += ".prototype";
        }

        Node property = call.getChildAtIndex(2);

        Node getPropNode = NodeUtil.newQName(
                compiler, target + "." + property.getString()).srcrefTree(call);

        if (callee.matchesQualifiedName(CR_DEFINE_PROPERTY)) {
            setJsDocWithType(getPropNode, getTypeByCrPropertyKind(call.getChildAtIndex(3)));
        } else {
            setJsDocWithType(getPropNode, new Node(Token.QMARK));
        }

        Node definitionNode = IR.exprResult(getPropNode).srcref(parent);

        parent.getParent().addChildAfter(definitionNode, parent);
    }

    private Node getTypeByCrPropertyKind(Node propertyKind) {
        if (propertyKind == null || propertyKind.matchesQualifiedName("cr.PropertyKind.JS")) {
            return new Node(Token.QMARK);
        }
        if (propertyKind.matchesQualifiedName("cr.PropertyKind.ATTR")) {
            return IR.string("string");
        }
        if (propertyKind.matchesQualifiedName("cr.PropertyKind.BOOL_ATTR")) {
            return IR.string("boolean");
        }
        compiler.report(JSError.make(propertyKind, CR_DEFINE_PROPERTY_INVALID_PROPERTY_KIND,
                propertyKind.getQualifiedName()));
        return null;
    }

    private void setJsDocWithType(Node target, Node type) {
        JSDocInfoBuilder builder = new JSDocInfoBuilder(false);
        builder.recordType(new JSTypeExpression(type, ""));
        target.setJSDocInfo(builder.build());
    }

    private boolean visitMakePublic(Node call, Node exprResult) {
        boolean changesMade = false;
        Node scope = exprResult.getParent();
        String className = call.getChildAtIndex(1).getQualifiedName();
        String prototype = className  + ".prototype";
        Node methods = call.getChildAtIndex(2);

        if (methods == null || !methods.isArrayLit()) {
            compiler.report(JSError.make(exprResult, CR_MAKE_PUBLIC_INVALID_SECOND_ARGUMENT));
            return changesMade;
        }

        Set<String> methodNames = new HashSet<>();
        for (Node methodName: methods.children()) {
            if (!methodName.isString()) {
                compiler.report(JSError.make(methodName, CR_MAKE_PUBLIC_INVALID_SECOND_ARGUMENT));
                return changesMade;
            }
            methodNames.add(methodName.getString());
        }

        for (Node child: scope.children()) {
            if (isAssignmentToPrototype(child, prototype)) {
                Node objectLit = child.getFirstChild().getChildAtIndex(1);
                for (Node stringKey : objectLit.children()) {
                    String field = stringKey.getString();
                    changesMade |= maybeAddPublicDeclaration(field, methodNames, className,
                                                             stringKey, scope, exprResult);
                }
            } else if (isAssignmentToPrototypeMethod(child, prototype)) {
                Node assignNode = child.getFirstChild();
                String qualifiedName = assignNode.getFirstChild().getQualifiedName();
                String field = qualifiedName.substring(qualifiedName.lastIndexOf('.') + 1);
                changesMade |= maybeAddPublicDeclaration(field, methodNames, className,
                                                         assignNode, scope, exprResult);
            } else if (isDummyPrototypeMethodDeclaration(child, prototype)) {
                String qualifiedName = child.getFirstChild().getQualifiedName();
                String field = qualifiedName.substring(qualifiedName.lastIndexOf('.') + 1);
                changesMade |= maybeAddPublicDeclaration(field, methodNames, className,
                                                         child.getFirstChild(), scope, exprResult);
            }
        }

        for (String missedDeclaration : methodNames) {
            compiler.report(JSError.make(exprResult, CR_MAKE_PUBLIC_MISSED_DECLARATION, className,
                    missedDeclaration));
        }

        return changesMade;
    }

    private boolean isAssignmentToPrototype(Node node, String prototype) {
        Node assignNode;
        return node.isExprResult() && (assignNode = node.getFirstChild()).isAssign() &&
                assignNode.getFirstChild().getQualifiedName().equals(prototype);
    }

    private boolean isAssignmentToPrototypeMethod(Node node, String prototype) {
        Node assignNode;
        return node.isExprResult() && (assignNode = node.getFirstChild()).isAssign() &&
                assignNode.getFirstChild().getQualifiedName().startsWith(prototype + ".");
    }

    private boolean isDummyPrototypeMethodDeclaration(Node node, String prototype) {
        Node getPropNode;
        return node.isExprResult() && (getPropNode = node.getFirstChild()).isGetProp() &&
                getPropNode.getQualifiedName().startsWith(prototype + ".");
    }

    private boolean maybeAddPublicDeclaration(String field, Set<String> publicAPIStrings,
            String className, Node jsDocSourceNode, Node scope, Node exprResult) {
        boolean changesMade = false;
        if (field.endsWith("_")) {
            String publicName = field.substring(0, field.length() - 1);
            if (publicAPIStrings.contains(publicName)) {
                Node methodDeclaration = NodeUtil.newQName(compiler, className + "." + publicName);
                if (jsDocSourceNode.getJSDocInfo() != null) {
                    methodDeclaration.setJSDocInfo(jsDocSourceNode.getJSDocInfo());
                    scope.addChildBefore(
                            IR.exprResult(methodDeclaration).srcrefTree(exprResult),
                            exprResult);
                    changesMade = true;
                } else {
                    compiler.report(JSError.make(jsDocSourceNode, CR_MAKE_PUBLIC_HAS_NO_JSDOC));
                }
                publicAPIStrings.remove(publicName);
            }
        }
        return changesMade;
    }

    private void visitExportPath(Node crExportPathNode, Node parent) {
        if (crExportPathNode.getChildCount() < 2) {
            compiler.report(JSError.make(crExportPathNode, CR_EXPORT_PATH_TOO_FEW_ARGUMENTS));
            return;
        }

        Node pathArg = crExportPathNode.getChildAtIndex(1);
        if (pathArg.isString()) {
            // TODO(dbeam): support cr.exportPath('ns').value.
            createAndInsertObjectsForQualifiedName(parent, pathArg.getString());
        }
    }

    private void createAndInsertObjectsForQualifiedName(Node scriptChild, String namespace) {
        List<Node> objectsForQualifiedName = createObjectsForQualifiedName(namespace);
        for (Node n : objectsForQualifiedName) {
            scriptChild.getParent().addChildBefore(n, scriptChild);
        }
    }

    private void visitNamespaceDefinition(Node crDefineCallNode, Node parent) {
        if (crDefineCallNode.getChildCount() != 3) {
            compiler.report(JSError.make(crDefineCallNode, CR_DEFINE_WRONG_NUMBER_OF_ARGUMENTS));
        }

        Node namespaceArg = crDefineCallNode.getChildAtIndex(1);
        Node function = crDefineCallNode.getChildAtIndex(2);

        if (!namespaceArg.isString()) {
            compiler.report(JSError.make(namespaceArg, CR_DEFINE_INVALID_FIRST_ARGUMENT));
            return;
        }

        // TODO(vitalyp): Check namespace name for validity here. It should be a valid chain of
        // identifiers.
        String namespace = namespaceArg.getString();

        createAndInsertObjectsForQualifiedName(parent, namespace);

        if (!function.isFunction()) {
            compiler.report(JSError.make(namespaceArg, CR_DEFINE_INVALID_SECOND_ARGUMENT));
            return;
        }

        Node returnNode, objectLit;
        Node functionBlock = function.getLastChild();
        if ((returnNode = functionBlock.getLastChild()) == null ||
                !returnNode.isReturn() ||
                (objectLit = returnNode.getFirstChild()) == null ||
                !objectLit.isObjectLit()) {
            compiler.report(JSError.make(namespaceArg, CR_DEFINE_INVALID_RETURN_IN_FUNCTION));
            return;
        }

        Map<String, String> exports = objectLitToMap(objectLit);

        NodeTraversal.traverse(compiler, functionBlock, new RenameInternalsToExternalsCallback(
                namespace, exports, functionBlock));
    }

    private Map<String, String> objectLitToMap(Node objectLit) {
        Map<String, String> res = new HashMap<String, String>();

        for (Node keyNode : objectLit.children()) {
            String key = keyNode.getString();

            Node valueNode = keyNode.getFirstChild();
            if (valueNode.isName()) {
                String value = keyNode.getFirstChild().getString();
                res.put(value, key);
            }
        }

        return res;
    }

    /**
     * For a string "a.b.c" produce the following JS IR:
     *
     * <p><pre>
     * var a = a || {};
     * a.b = a.b || {};
     * a.b.c = a.b.c || {};</pre>
     */
    private List<Node> createObjectsForQualifiedName(String namespace) {
        List<Node> objects = new ArrayList<>();
        String[] parts = namespace.split("\\.");

        createObjectIfNew(objects, parts[0], true);

        if (parts.length >= 2) {
            StringBuilder currPrefix = new StringBuilder().append(parts[0]);
            for (int i = 1; i < parts.length; ++i) {
                currPrefix.append(".").append(parts[i]);
                createObjectIfNew(objects, currPrefix.toString(), false);
            }
        }

        return objects;
    }

    private void createObjectIfNew(List<Node> objects, String name, boolean needVar) {
        if (!createdObjects.contains(name)) {
            objects.add(createJsNode((needVar ? "var " : "") + name + " = " + name + " || {};"));
            createdObjects.add(name);
        }
    }

    private Node createJsNode(String code) {
        // The parent node after parseSyntheticCode() is SCRIPT node, we need to get rid of it.
        return compiler.parseSyntheticCode(code).removeFirstChild();
    }

    private class RenameInternalsToExternalsCallback extends AbstractPostOrderCallback {
        private final String namespaceName;
        private final Map<String, String> exports;
        private final Node namespaceBlock;

        public RenameInternalsToExternalsCallback(String namespaceName,
                Map<String, String> exports, Node namespaceBlock) {
            this.namespaceName = namespaceName;
            this.exports = exports;
            this.namespaceBlock = namespaceBlock;
        }

        @Override
        public void visit(NodeTraversal t, Node n, Node parent) {
            if (n.isFunction() && parent == this.namespaceBlock &&
                    this.exports.containsKey(n.getFirstChild().getString())) {
                // It's a top-level function/constructor definition.
                //
                // Change
                //
                //   /** Some doc */
                //   function internalName() {}
                //
                // to
                //
                //   /** Some doc */
                //   my.namespace.name.externalName = function internalName() {};
                //
                // by looking up in this.exports for internalName to find the correspondent
                // externalName.
                Node functionTree = n.cloneTree();
                Node exprResult = IR.exprResult(
                            IR.assign(buildQualifiedName(n.getFirstChild()), functionTree).srcref(n)
                        ).srcref(n);

                if (n.getJSDocInfo() != null) {
                    exprResult.getFirstChild().setJSDocInfo(n.getJSDocInfo());
                    functionTree.removeProp(Node.JSDOC_INFO_PROP);
                }
                this.namespaceBlock.replaceChild(n, exprResult);
            } else if (n.isName() && this.exports.containsKey(n.getString()) &&
                    !parent.isFunction()) {
                if (parent.isVar()) {
                    if (parent.getParent() == this.namespaceBlock) {
                        // It's a top-level exported variable definition (maybe without an
                        // assignment).
                        // Change
                        //
                        //   var enum = { 'one': 1, 'two': 2 };
                        //
                        // to
                        //
                        //   my.namespace.name.enum = { 'one': 1, 'two': 2 };
                        Node varContent = n.removeFirstChild();
                        Node exprResult;
                        if (varContent == null) {
                            exprResult = IR.exprResult(buildQualifiedName(n)).srcref(parent);
                        } else {
                            exprResult = IR.exprResult(
                                        IR.assign(buildQualifiedName(n), varContent).srcref(parent)
                                    ).srcref(parent);
                        }
                        if (parent.getJSDocInfo() != null) {
                            exprResult.getFirstChild().setJSDocInfo(parent.getJSDocInfo().clone());
                        }
                        this.namespaceBlock.replaceChild(parent, exprResult);
                    }
                } else {
                    // It's a local name referencing exported entity. Change to its global name.
                    Node newNode = buildQualifiedName(n);
                    if (n.getJSDocInfo() != null) {
                        newNode.setJSDocInfo(n.getJSDocInfo().clone());
                    }

                    // If we alter the name of a called function, then it gets an explicit "this"
                    // value.
                    if (parent.isCall()) {
                        parent.putBooleanProp(Node.FREE_CALL, false);
                    }

                    parent.replaceChild(n, newNode);
                }
            }
        }

        private Node buildQualifiedName(Node internalName) {
            String externalName = this.exports.get(internalName.getString());
            return NodeUtil.newQName(compiler, this.namespaceName + "." + externalName).srcrefTree(
                    internalName);
        }
    }
}
