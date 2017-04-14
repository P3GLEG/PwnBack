package com.k4ch0w.pwnback;

import org.xml.sax.SAXException;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.Enumeration;

class PwnBackWebTree extends JPanel {
    private DefaultMutableTreeNode rootNode;
    private DefaultTreeModel treeModel;
    private JTree tree;


    PwnBackWebTree() {
        super(new GridLayout(1, 0));
        rootNode = new DefaultMutableTreeNode(new PwnBackNode("/"));
        treeModel = new DefaultTreeModel(rootNode);
        tree = new JTree(treeModel);
        tree.setEditable(false);
        tree.getSelectionModel().setSelectionMode
                (TreeSelectionModel.SINGLE_TREE_SELECTION);
        tree.setShowsRootHandles(true);
        tree.addMouseListener(new PwnBackTreeMouseListener());
        JScrollPane scrollPane = new JScrollPane(tree);
        add(scrollPane);
    }

    DefaultTreeModel getTree() {
        return treeModel;
    }


    private DefaultMutableTreeNode pathExists(DefaultMutableTreeNode parent, String path) {
        if (parent == null) {
            parent = rootNode;
        }
        for (Enumeration node = parent.breadthFirstEnumeration(); node.hasMoreElements(); ) {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) node.nextElement();
            PwnBackNode usrNode = (PwnBackNode) child.getUserObject();
            if (usrNode.getPath().equals(path)) {
                return child;
            }
        }
        return null;
    }

    void addTreeNode(PwnBackNode node) {
        String[] temp = node.getPath().split("/");
        addTreeNode(null, temp, node.getFirstDocument());
    }

    private String[] removeEmptyOrNull(String[] paths) {
        while (paths[0] == null || paths[0].equals("")) {
            paths = Arrays.copyOfRange(paths, 1, paths.length);
        }
        return paths;
    }

    private boolean isLeafPath(String[] paths) {
        return paths.length == 1;
    }

    private void addNewLeaf(DefaultMutableTreeNode parent, DefaultMutableTreeNode child, PwnBackNode newNode) {
        if (child == null) {
            addChildNode(parent, newNode, false);
        } else {
            PwnBackNode existingNode = (PwnBackNode) child.getUserObject();
            existingNode.addDocument(newNode.getFirstDocument());
        }
    }

    private DefaultMutableTreeNode addNewChildNode(DefaultMutableTreeNode parent, DefaultMutableTreeNode child, PwnBackNode newNode) {
        if (child == null) {
            if (parent.equals(rootNode)) {
                return addChildNode(parent, newNode, true);
            } else {
                return addChildNode(parent, newNode, false);
            }
        }
        return null;
    }

    private void addTreeNode(DefaultMutableTreeNode parent, String[] paths, PwnBackDocument doc) {
        if (parent == null) {
            parent = rootNode;
        }
        paths = removeEmptyOrNull(paths);
        String currentPath = paths[0];
        DefaultMutableTreeNode child;
        child = pathExists(parent, currentPath);
        PwnBackNode newNode = new PwnBackNode(currentPath, doc);
        if (isLeafPath(paths)) {
            addNewLeaf(parent, child, newNode);
        } else {
            child = addNewChildNode(parent, child, newNode);
            addTreeNode(child, Arrays.copyOfRange(paths, 1, paths.length), doc);
        }
    }


    private DefaultMutableTreeNode addChildNode(final DefaultMutableTreeNode parent,
                                                Object child,
                                                boolean shouldBeVisible) {

        DefaultMutableTreeNode childNode = new DefaultMutableTreeNode(child);

        if (SwingUtilities.isEventDispatchThread()) {
            treeModel.insertNodeInto(childNode, parent,
                    parent.getChildCount());
        } else {
            try {
                SwingUtilities.invokeAndWait(() -> treeModel.insertNodeInto(childNode, parent,
                        parent.getChildCount()));
            } catch (InterruptedException | InvocationTargetException e) {
                e.printStackTrace();
            }
        }

        if (shouldBeVisible) {
            tree.scrollPathToVisible(new TreePath(childNode.getPath()));
        }
        return childNode;
    }

    private class PwnBackTreeMouseListener extends MouseAdapter {
        public void mouseClicked(MouseEvent e) {
            if (e.getClickCount() == 2) {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode)
                        tree.getLastSelectedPathComponent();
                if (node == null) return;
                PwnBackNode nodeInfo = (PwnBackNode) node.getUserObject();
                PwnBackDocumentFrame docPanel;
                try {
                    docPanel = new PwnBackDocumentFrame(nodeInfo.getDocuments());
                    docPanel.setTitle(nodeInfo.getPath());
                    docPanel.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                    docPanel.setVisible(true);
                } catch (IOException | SAXException e1) {
                    e1.printStackTrace();
                }

            }
        }
    }
}



