const { MerkleTree } = require("merkletreejs");
const keccak256 = require("keccak256");

let whiteListAddresses = [
  "0x172ADF1549518f27091A85b7F63A8bBe1300ffB4",
  "0x0D0707963952f2fBA59dD06f2b425ace40b492Fe",
  "0x2d6096551e9c9ab7aadaec4d962566bdbd03a3bf",
  "0x67b6d479c7bb412c54e03dca8e1bc6740ce6b99c",
  "0xc4ccddcd0239d8425b54322e8e5f99d19fb7ba43",
  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
  "0x6b0b3a982b4634ac68dd83a4dbf02311ce324181",
];

/*
 * Get Leaf Nodes - Hash of all 7 addresses
 */

const leafNodes = whiteListAddresses.map((address) => keccak256(address));

/*
 * Create Merkle Tree
 * console.log(merkleTree.toString());
 */

const merkleTree = new MerkleTree(leafNodes, keccak256, { sort: true });

/*
 * Get Root Hash
 */

const rootHash = merkleTree.getRoot();

/*
 * Get Merkle Proof
 * HexProof returns neighbour leaf, all neighbour parent nodes that will be required to derive merkle tree root hash
 * console.log(claimingLeafNode.toString("hex"));
 */

const claimingAddress = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
const claimingLeafNode = keccak256(claimingAddress);

const hexProof = merkleTree.getHexProof(claimingLeafNode);

/*
 * Verification of a Whitelist Address
 */

const isWhitlistedAddress = merkleTree.verify(
  hexProof,
  claimingLeafNode,
  rootHash
);

console.log(
  isWhitlistedAddress ? "Verification Successfull" : "Verification Failed"
);

/*
 * Verification in Solidity Smart Contract
 * 1) Import Library
    https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/MerkleProof.sol
 * 2) 
    bytes32 public merkleRoot = Set Root Hash
 * 3) 
    function verify(bytes32[] calldata _merkleProof) {
       bytes32 leaf = keccack256(abi.encodePacked(msg.sender));
       require(MerkleProof.verify(_merkleProof, merkleRoot, leaf), "Invalid Proof!");
    }
 */
