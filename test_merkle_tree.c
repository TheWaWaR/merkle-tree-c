
#define CBMT_NODE_I32

#include "merkle_tree.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

cbmt_node int32_to_node(int32_t value) {
  cbmt_node node;
  memcpy(node.bytes, &value, sizeof(value));
  return node;
}

int32_t node_to_int32(cbmt_node node) {
  return *((int32_t *)node.bytes);
}

void test_build_empty();
void test_build_five();
void test_build_root_directly();
void test_rebuild_proof();
void test_build_proof();

int main() {
  test_build_empty();
  test_build_five();
  test_build_root_directly();
  test_rebuild_proof();
  test_build_proof();
}

void test_build_empty() {
  cbmt_node nodes[1024];
  cbmt_node leaf_nodes[256];

  cbmt_buffer nodes_buffer;
  nodes_buffer.data = nodes;
  nodes_buffer.capacity = sizeof(nodes);

  int ret;
  cbmt_tree tree;
  cbmt_leaves leaves;
  leaves.nodes = leaf_nodes;
  leaves.length = 0;
  ret = cbmt_build_merkle_tree(&tree, &leaves, nodes_buffer);
  assert(ret == 0);
  assert(node_to_int32(cbmt_tree_root(&tree)) == 0);
  return;
}

void test_build_five() {
  cbmt_node nodes[1024];
  cbmt_node leaf_nodes[256];

  cbmt_buffer nodes_buffer;
  nodes_buffer.data = nodes;
  nodes_buffer.capacity = sizeof(nodes);

  int ret;
  cbmt_tree tree;
  cbmt_leaves leaves;
  leaves.nodes = leaf_nodes;
  leaves.length = 5;
  leaves.nodes[0] = int32_to_node(2);
  leaves.nodes[1] = int32_to_node(3);
  leaves.nodes[2] = int32_to_node(5);
  leaves.nodes[3] = int32_to_node(7);
  leaves.nodes[4] = int32_to_node(11);
  ret = cbmt_build_merkle_tree(&tree, &leaves, nodes_buffer);
  assert(ret == 0);

  for (size_t i = 0; i < tree.length; i++) {
    printf("tree.nodes[%ld]: %d\n", i, node_to_int32(tree.nodes[i]));
  }
  assert(node_to_int32(tree.nodes[0]) == 4);
  assert(node_to_int32(tree.nodes[1]) == -2);
  assert(node_to_int32(tree.nodes[2]) == 2);
  assert(node_to_int32(tree.nodes[3]) == 4);

  assert(node_to_int32(tree.nodes[4]) == 2);
  assert(node_to_int32(tree.nodes[5]) == 3);
  assert(node_to_int32(tree.nodes[6]) == 5);
  assert(node_to_int32(tree.nodes[7]) == 7);
  assert(node_to_int32(tree.nodes[8]) == 11);
  return;
}

void test_build_root_directly() {
  cbmt_node nodes[1024];
  cbmt_node leaf_nodes[256];

  cbmt_buffer nodes_buffer;
  nodes_buffer.data = nodes;
  nodes_buffer.capacity = sizeof(nodes);

  int ret;
  cbmt_tree tree;
  cbmt_leaves leaves;
  leaves.nodes = leaf_nodes;
  leaves.length = 5;
  leaves.nodes[0] = int32_to_node(2);
  leaves.nodes[1] = int32_to_node(3);
  leaves.nodes[2] = int32_to_node(5);
  leaves.nodes[3] = int32_to_node(7);
  leaves.nodes[4] = int32_to_node(11);
  cbmt_node root;
  ret = cbmt_build_merkle_root(&root, &leaves, nodes_buffer);
  assert(ret == 0);
  printf("root: %d\n", node_to_int32(root));
  assert(node_to_int32(root) == 4);
}

void test_rebuild_proof() {
  cbmt_node nodes[1024];
  cbmt_node leaf_nodes[256];

  cbmt_buffer nodes_buffer;
  nodes_buffer.data = nodes;
  nodes_buffer.capacity = sizeof(nodes);

  int ret;
  cbmt_tree tree;
  cbmt_leaves leaves;
  leaves.nodes = leaf_nodes;
  leaves.length = 5;
  leaves.nodes[0] = int32_to_node(2);
  leaves.nodes[1] = int32_to_node(3);
  leaves.nodes[2] = int32_to_node(5);
  leaves.nodes[3] = int32_to_node(7);
  leaves.nodes[4] = int32_to_node(11);
  ret = cbmt_build_merkle_tree(&tree, &leaves, nodes_buffer);
  assert(ret == 0);

  cbmt_node root = cbmt_tree_root(&tree);
  cbmt_proof proof;
  uint32_t leaf_index_values[2] = { 0, 3 };
  cbmt_indices leaf_indices;
  leaf_indices.values = leaf_index_values;
  leaf_indices.length = 2;
  leaf_indices.capacity = 2;

  uint32_t leaf_values_buffer[256];
  cbmt_node lemmas_nodes[256];
  cbmt_buffer indices_buffer;
  cbmt_buffer lemmas_buffer;
  indices_buffer.data = leaf_values_buffer;
  indices_buffer.capacity = 256;
  lemmas_buffer.data = lemmas_nodes;
  lemmas_buffer.capacity = 256;
  ret = cbmt_tree_build_proof(&proof, &tree, &leaf_indices, indices_buffer, lemmas_buffer);
  assert(ret == 0);
  printf("proof.indices.length=%ld, proof.lemmas_length=%ld\n",
         proof.indices.length,
         proof.lemmas_length);
  assert(proof.indices.length == 2);
  assert(proof.indices.values[0] == 4);
  assert(proof.indices.values[1] == 7);
  assert(proof.lemmas_length == 2);
  assert(node_to_int32(proof.lemmas[0]) == 11);
  assert(node_to_int32(proof.lemmas[1]) == 2);

  cbmt_node needed_nodes[256];
  cbmt_leaves needed_leaves;
  needed_leaves.nodes = needed_nodes;
  needed_leaves.length = leaf_indices.length;
  for (size_t i = 0; i < needed_leaves.length; i++) {
    needed_leaves.nodes[i] = tree.nodes[proof.indices.values[i]];
    printf("[needed] index=%d, node=%d\n",
           proof.indices.values[i],
           node_to_int32(tree.nodes[proof.indices.values[i]]));
  }


  cbmt_node nodes2[1024];
  cbmt_node_pair pairs[1024];
  cbmt_buffer nodes_buffer2;
  cbmt_buffer pairs_buffer;
  nodes_buffer2.data = nodes2;
  nodes_buffer2.capacity = sizeof(nodes2);
  pairs_buffer.data = pairs;
  pairs_buffer.capacity = sizeof(pairs);
  ret = cbmt_proof_verify(&proof, &root, &needed_leaves, nodes_buffer2, pairs_buffer);
  assert(ret == 0);
  return;
}

void test_build_proof() {
  return;
}
