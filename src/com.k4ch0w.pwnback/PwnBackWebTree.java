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
        tree.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    DefaultMutableTreeNode node = (DefaultMutableTreeNode)
                            tree.getLastSelectedPathComponent();
                    if (node == null) return;
                    PwnBackNode nodeInfo = (PwnBackNode) node.getUserObject();
                    DocumentFrame docPanel;
                    try {
                        docPanel = new DocumentFrame(nodeInfo.getDocuments());
                        docPanel.setTitle(nodeInfo.getPath());
                        docPanel.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                        docPanel.setVisible(true);
                    } catch (IOException | SAXException e1) {
                        e1.printStackTrace();
                    }

                }
            }
        });
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

    private void addTreeNode(DefaultMutableTreeNode parent, String[] paths, PwnBackDocument doc) {
        DefaultMutableTreeNode child;
        while (paths[0] == null || paths[0].equals("")) {
            paths = Arrays.copyOfRange(paths, 1, paths.length);
        }
        if (parent == null) {
            parent = rootNode;
        }
        PwnBackNode newNode = new PwnBackNode(paths[0], doc);
        if (paths.length == 1) {
            child = pathExists(parent, paths[0]);
            if (child == null) {
                addObject(parent, newNode, false);
            } else {
                PwnBackNode existingNode = (PwnBackNode) child.getUserObject();
                existingNode.addDocument(doc);
            }
        } else {
            child = pathExists(parent, paths[0]);
            if (child == null) {
                //New Leaf
                if (parent.equals(rootNode)) {
                    child = addObject(parent, newNode, true);
                } else {
                    child = addObject(parent, newNode, false);
                }
            }
            addTreeNode(child, Arrays.copyOfRange(paths, 1, paths.length), doc);
        }
    }


    private DefaultMutableTreeNode addObject(final DefaultMutableTreeNode parent,
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

}



