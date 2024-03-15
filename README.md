# Network Handshake Rust Project

This Rust project allows users to perform a protocol-level network handshake with either an Ethereum or a Bitcoin node. The project transfers and parses only information relevant to completing the handshake and does not proceed with any communication thereafter.

## Requirements
- Rust programming language (installation instructions can be found [here](https://www.rust-lang.org/tools/install))
- Cargo package manager (usually installed with Rust)

## Usage

1. **Clone the Repository**

   ```bash
   git clone https://github.com/dandoii/node_handshake.git
   cd node_handshake
   ```
2. **Run the Project**
    ```bash
   cargo run
   ```
3. **Enter the Necessary Information**
    1. Enter eith b or e to indicate which handshake you'd wish to have performed.
    2. Enter the address and port of the node in the format {adrr}:{port}.
    3. If using Ethereum, enter the public key of the node next.
4. **Determining a Successful Handshake**
    1. Bitcoin
        Upon a successful handshake with a bitcoin node, the version message will be sent, received and sent back. After the verack message is sent to the target node, it will send back a message. The protocol dictates that this should be a verack message, but often this will be skipped and a sendcmpt command will be returned. This will be outputted by the program along with the command bytes which can be converted to ASCII.
    2. Ethereum
        Upon successful handshake with an Ethereum Node, the relevant secrets exchanged will be verified and if matched, a success message along with both hashes will printed.
5. **EXAMPLES**
   1. Bitcoin

      89.38.98.211:8333
      
      178.162.165.203:8333
      
   2. Ethereum
      
         000314fd109a892573fe8ca8adfd2ed2a5259b3ca98a9b5a2e7f6fa495b5f258565861bf378cb4c2f250a06d9aa008d770c9c87a7364ae25fb3f29fa92af375f 23.92.70.178:30304
