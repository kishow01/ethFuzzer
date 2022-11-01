DEFAULT_BLOCKCHAIN_KEY_LOCATION = '../blockchain/keys.json'
DEFAULT_BLOCKCHAIN_PORT = 8545

BLOCK_TAG_EARLIEST = "earliest"
BLOCK_TAG_LATEST   = "latest"
BLOCK_TAG_PENDING  = "pending"
BLOCK_TAGS = (
    BLOCK_TAG_EARLIEST,
    BLOCK_TAG_LATEST,
    BLOCK_TAG_PENDING,
)

# solcx supported compiler version: https://solcx.readthedocs.io/en/latest/index.html
SUPPORTED_COMPILER_VERSION = (
    '0.5.0',
    '0.5.1',
    '0.5.2',
    '0.5.3',
    '0.5.4',
    '0.5.5',
    '0.5.6',
    '0.5.7',
    '0.5.8',
    '0.5.9',
    '0.5.10',
    '0.5.11',
    '0.5.12',
    '0.5.13',
    '0.5.14',
    '0.5.15',
    '0.5.16',
    '0.5.17',
    '0.6.0',
    '0.6.1',
    '0.6.2',
    '0.6.3',
    '0.6.4',
    '0.6.5',
    '0.6.6',
    '0.6.7',
    '0.6.8',
    '0.6.9',
    '0.6.10',
    '0.6.11',
    '0.6.12',
    '0.7.0',
    '0.7.1',
    '0.7.2',
    '0.7.3',
    '0.7.4',
    '0.7.5',
    '0.7.6',
    '0.8.0',
    '0.8.1',
    '0.8.2',
    '0.8.3',
    '0.8.4',
    '0.8.5',
    '0.8.6',
    '0.8.7',
    '0.8.8',
    '0.8.9',
    '0.8.10',
    '0.8.11',
    '0.8.12',
    '0.8.13',
    '0.8.14',
    '0.8.15',
    '0.8.16',
    '0.8.17',
)

# Contract ABI Specification Type, version 0.8.16: https://docs.soliditylang.org/en/v0.8.16/abi-spec.html
# NOT INCLUDE ARRAY TYPE AND NON-FIXED-SIZE TYPE
ABI_SPECIFICATION_TYPE = (
    'uint8', 'uint16', 'uint24', 'uint32', 'uint40', 'uint48', 'uint56', 'uint64', 
    'uint72', 'uint80', 'uint88', 'uint96', 'uint104', 'uint112', 'uint120', 'uint128', 
    'uint136', 'uint144', 'uint152', 'uint160', 'uint168', 'uint176', 'uint184', 'uint192', 
    'uint200', 'uint208', 'uint216', 'uint224', 'uint232', 'uint240', 'uint248', 'uint256',

    'int8', 'int16', 'int24', 'int32', 'int40', 'int48', 'int56', 'int64', 
    'int72', 'int80', 'int88', 'int96', 'int104', 'int112', 'int120', 'int128', 
    'int136', 'int144', 'int152', 'int160', 'int168', 'int176', 'int184', 'int192',
    'int200', 'int208', 'int216', 'int224', 'int232', 'int240', 'int248', 'int256',

    'address',

    'uint', 'int',

    'bool',

    'fixed8x1', 'fixed8x2', 'fixed8x3', 'fixed8x4', 'fixed8x5', 'fixed8x6', 'fixed8x7', 'fixed8x8', 'fixed8x9', 'fixed8x10', 'fixed8x11', 'fixed8x12', 'fixed8x13', 'fixed8x14', 'fixed8x15', 'fixed8x16', 'fixed8x17', 'fixed8x18', 'fixed8x19', 'fixed8x20', 'fixed8x21', 'fixed8x22', 'fixed8x23', 'fixed8x24', 'fixed8x25', 'fixed8x26', 'fixed8x27', 'fixed8x28', 'fixed8x29', 'fixed8x30', 'fixed8x31', 'fixed8x32', 'fixed8x33', 'fixed8x34', 'fixed8x35', 'fixed8x36', 'fixed8x37', 'fixed8x38', 'fixed8x39', 'fixed8x40', 'fixed8x41', 'fixed8x42', 'fixed8x43', 'fixed8x44', 'fixed8x45', 'fixed8x46', 'fixed8x47', 'fixed8x48', 'fixed8x49', 'fixed8x50', 'fixed8x51', 'fixed8x52', 'fixed8x53', 'fixed8x54', 'fixed8x55', 'fixed8x56', 'fixed8x57', 'fixed8x58', 'fixed8x59', 'fixed8x60', 'fixed8x61', 'fixed8x62', 'fixed8x63', 'fixed8x64', 'fixed8x65', 'fixed8x66', 'fixed8x67', 'fixed8x68', 'fixed8x69', 'fixed8x70', 'fixed8x71', 'fixed8x72', 'fixed8x73', 'fixed8x74', 'fixed8x75', 'fixed8x76', 'fixed8x77', 'fixed8x78', 'fixed8x79', 'fixed8x80', 
    'fixed16x1', 'fixed16x2', 'fixed16x3', 'fixed16x4', 'fixed16x5', 'fixed16x6', 'fixed16x7', 'fixed16x8', 'fixed16x9', 'fixed16x10', 'fixed16x11', 'fixed16x12', 'fixed16x13', 'fixed16x14', 'fixed16x15', 'fixed16x16', 'fixed16x17', 'fixed16x18', 'fixed16x19', 'fixed16x20', 'fixed16x21', 'fixed16x22', 'fixed16x23', 'fixed16x24', 'fixed16x25', 'fixed16x26', 'fixed16x27', 'fixed16x28', 'fixed16x29', 'fixed16x30', 'fixed16x31', 'fixed16x32', 'fixed16x33', 'fixed16x34', 'fixed16x35', 'fixed16x36', 'fixed16x37', 'fixed16x38', 'fixed16x39', 'fixed16x40', 'fixed16x41', 'fixed16x42', 'fixed16x43', 'fixed16x44', 'fixed16x45', 'fixed16x46', 'fixed16x47', 'fixed16x48', 'fixed16x49', 'fixed16x50', 'fixed16x51', 'fixed16x52', 'fixed16x53', 'fixed16x54', 'fixed16x55', 'fixed16x56', 'fixed16x57', 'fixed16x58', 'fixed16x59', 'fixed16x60', 'fixed16x61', 'fixed16x62', 'fixed16x63', 'fixed16x64', 'fixed16x65', 'fixed16x66', 'fixed16x67', 'fixed16x68', 'fixed16x69', 'fixed16x70', 'fixed16x71', 'fixed16x72', 'fixed16x73', 'fixed16x74', 'fixed16x75', 'fixed16x76', 'fixed16x77', 'fixed16x78', 'fixed16x79', 'fixed16x80', 
    'fixed24x1', 'fixed24x2', 'fixed24x3', 'fixed24x4', 'fixed24x5', 'fixed24x6', 'fixed24x7', 'fixed24x8', 'fixed24x9', 'fixed24x10', 'fixed24x11', 'fixed24x12', 'fixed24x13', 'fixed24x14', 'fixed24x15', 'fixed24x16', 'fixed24x17', 'fixed24x18', 'fixed24x19', 'fixed24x20', 'fixed24x21', 'fixed24x22', 'fixed24x23', 'fixed24x24', 'fixed24x25', 'fixed24x26', 'fixed24x27', 'fixed24x28', 'fixed24x29', 'fixed24x30', 'fixed24x31', 'fixed24x32', 'fixed24x33', 'fixed24x34', 'fixed24x35', 'fixed24x36', 'fixed24x37', 'fixed24x38', 'fixed24x39', 'fixed24x40', 'fixed24x41', 'fixed24x42', 'fixed24x43', 'fixed24x44', 'fixed24x45', 'fixed24x46', 'fixed24x47', 'fixed24x48', 'fixed24x49', 'fixed24x50', 'fixed24x51', 'fixed24x52', 'fixed24x53', 'fixed24x54', 'fixed24x55', 'fixed24x56', 'fixed24x57', 'fixed24x58', 'fixed24x59', 'fixed24x60', 'fixed24x61', 'fixed24x62', 'fixed24x63', 'fixed24x64', 'fixed24x65', 'fixed24x66', 'fixed24x67', 'fixed24x68', 'fixed24x69', 'fixed24x70', 'fixed24x71', 'fixed24x72', 'fixed24x73', 'fixed24x74', 'fixed24x75', 'fixed24x76', 'fixed24x77', 'fixed24x78', 'fixed24x79', 'fixed24x80', 
    'fixed32x1', 'fixed32x2', 'fixed32x3', 'fixed32x4', 'fixed32x5', 'fixed32x6', 'fixed32x7', 'fixed32x8', 'fixed32x9', 'fixed32x10', 'fixed32x11', 'fixed32x12', 'fixed32x13', 'fixed32x14', 'fixed32x15', 'fixed32x16', 'fixed32x17', 'fixed32x18', 'fixed32x19', 'fixed32x20', 'fixed32x21', 'fixed32x22', 'fixed32x23', 'fixed32x24', 'fixed32x25', 'fixed32x26', 'fixed32x27', 'fixed32x28', 'fixed32x29', 'fixed32x30', 'fixed32x31', 'fixed32x32', 'fixed32x33', 'fixed32x34', 'fixed32x35', 'fixed32x36', 'fixed32x37', 'fixed32x38', 'fixed32x39', 'fixed32x40', 'fixed32x41', 'fixed32x42', 'fixed32x43', 'fixed32x44', 'fixed32x45', 'fixed32x46', 'fixed32x47', 'fixed32x48', 'fixed32x49', 'fixed32x50', 'fixed32x51', 'fixed32x52', 'fixed32x53', 'fixed32x54', 'fixed32x55', 'fixed32x56', 'fixed32x57', 'fixed32x58', 'fixed32x59', 'fixed32x60', 'fixed32x61', 'fixed32x62', 'fixed32x63', 'fixed32x64', 'fixed32x65', 'fixed32x66', 'fixed32x67', 'fixed32x68', 'fixed32x69', 'fixed32x70', 'fixed32x71', 'fixed32x72', 'fixed32x73', 'fixed32x74', 'fixed32x75', 'fixed32x76', 'fixed32x77', 'fixed32x78', 'fixed32x79', 'fixed32x80', 
    'fixed40x1', 'fixed40x2', 'fixed40x3', 'fixed40x4', 'fixed40x5', 'fixed40x6', 'fixed40x7', 'fixed40x8', 'fixed40x9', 'fixed40x10', 'fixed40x11', 'fixed40x12', 'fixed40x13', 'fixed40x14', 'fixed40x15', 'fixed40x16', 'fixed40x17', 'fixed40x18', 'fixed40x19', 'fixed40x20', 'fixed40x21', 'fixed40x22', 'fixed40x23', 'fixed40x24', 'fixed40x25', 'fixed40x26', 'fixed40x27', 'fixed40x28', 'fixed40x29', 'fixed40x30', 'fixed40x31', 'fixed40x32', 'fixed40x33', 'fixed40x34', 'fixed40x35', 'fixed40x36', 'fixed40x37', 'fixed40x38', 'fixed40x39', 'fixed40x40', 'fixed40x41', 'fixed40x42', 'fixed40x43', 'fixed40x44', 'fixed40x45', 'fixed40x46', 'fixed40x47', 'fixed40x48', 'fixed40x49', 'fixed40x50', 'fixed40x51', 'fixed40x52', 'fixed40x53', 'fixed40x54', 'fixed40x55', 'fixed40x56', 'fixed40x57', 'fixed40x58', 'fixed40x59', 'fixed40x60', 'fixed40x61', 'fixed40x62', 'fixed40x63', 'fixed40x64', 'fixed40x65', 'fixed40x66', 'fixed40x67', 'fixed40x68', 'fixed40x69', 'fixed40x70', 'fixed40x71', 'fixed40x72', 'fixed40x73', 'fixed40x74', 'fixed40x75', 'fixed40x76', 'fixed40x77', 'fixed40x78', 'fixed40x79', 'fixed40x80', 
    'fixed48x1', 'fixed48x2', 'fixed48x3', 'fixed48x4', 'fixed48x5', 'fixed48x6', 'fixed48x7', 'fixed48x8', 'fixed48x9', 'fixed48x10', 'fixed48x11', 'fixed48x12', 'fixed48x13', 'fixed48x14', 'fixed48x15', 'fixed48x16', 'fixed48x17', 'fixed48x18', 'fixed48x19', 'fixed48x20', 'fixed48x21', 'fixed48x22', 'fixed48x23', 'fixed48x24', 'fixed48x25', 'fixed48x26', 'fixed48x27', 'fixed48x28', 'fixed48x29', 'fixed48x30', 'fixed48x31', 'fixed48x32', 'fixed48x33', 'fixed48x34', 'fixed48x35', 'fixed48x36', 'fixed48x37', 'fixed48x38', 'fixed48x39', 'fixed48x40', 'fixed48x41', 'fixed48x42', 'fixed48x43', 'fixed48x44', 'fixed48x45', 'fixed48x46', 'fixed48x47', 'fixed48x48', 'fixed48x49', 'fixed48x50', 'fixed48x51', 'fixed48x52', 'fixed48x53', 'fixed48x54', 'fixed48x55', 'fixed48x56', 'fixed48x57', 'fixed48x58', 'fixed48x59', 'fixed48x60', 'fixed48x61', 'fixed48x62', 'fixed48x63', 'fixed48x64', 'fixed48x65', 'fixed48x66', 'fixed48x67', 'fixed48x68', 'fixed48x69', 'fixed48x70', 'fixed48x71', 'fixed48x72', 'fixed48x73', 'fixed48x74', 'fixed48x75', 'fixed48x76', 'fixed48x77', 'fixed48x78', 'fixed48x79', 'fixed48x80', 
    'fixed56x1', 'fixed56x2', 'fixed56x3', 'fixed56x4', 'fixed56x5', 'fixed56x6', 'fixed56x7', 'fixed56x8', 'fixed56x9', 'fixed56x10', 'fixed56x11', 'fixed56x12', 'fixed56x13', 'fixed56x14', 'fixed56x15', 'fixed56x16', 'fixed56x17', 'fixed56x18', 'fixed56x19', 'fixed56x20', 'fixed56x21', 'fixed56x22', 'fixed56x23', 'fixed56x24', 'fixed56x25', 'fixed56x26', 'fixed56x27', 'fixed56x28', 'fixed56x29', 'fixed56x30', 'fixed56x31', 'fixed56x32', 'fixed56x33', 'fixed56x34', 'fixed56x35', 'fixed56x36', 'fixed56x37', 'fixed56x38', 'fixed56x39', 'fixed56x40', 'fixed56x41', 'fixed56x42', 'fixed56x43', 'fixed56x44', 'fixed56x45', 'fixed56x46', 'fixed56x47', 'fixed56x48', 'fixed56x49', 'fixed56x50', 'fixed56x51', 'fixed56x52', 'fixed56x53', 'fixed56x54', 'fixed56x55', 'fixed56x56', 'fixed56x57', 'fixed56x58', 'fixed56x59', 'fixed56x60', 'fixed56x61', 'fixed56x62', 'fixed56x63', 'fixed56x64', 'fixed56x65', 'fixed56x66', 'fixed56x67', 'fixed56x68', 'fixed56x69', 'fixed56x70', 'fixed56x71', 'fixed56x72', 'fixed56x73', 'fixed56x74', 'fixed56x75', 'fixed56x76', 'fixed56x77', 'fixed56x78', 'fixed56x79', 'fixed56x80', 
    'fixed64x1', 'fixed64x2', 'fixed64x3', 'fixed64x4', 'fixed64x5', 'fixed64x6', 'fixed64x7', 'fixed64x8', 'fixed64x9', 'fixed64x10', 'fixed64x11', 'fixed64x12', 'fixed64x13', 'fixed64x14', 'fixed64x15', 'fixed64x16', 'fixed64x17', 'fixed64x18', 'fixed64x19', 'fixed64x20', 'fixed64x21', 'fixed64x22', 'fixed64x23', 'fixed64x24', 'fixed64x25', 'fixed64x26', 'fixed64x27', 'fixed64x28', 'fixed64x29', 'fixed64x30', 'fixed64x31', 'fixed64x32', 'fixed64x33', 'fixed64x34', 'fixed64x35', 'fixed64x36', 'fixed64x37', 'fixed64x38', 'fixed64x39', 'fixed64x40', 'fixed64x41', 'fixed64x42', 'fixed64x43', 'fixed64x44', 'fixed64x45', 'fixed64x46', 'fixed64x47', 'fixed64x48', 'fixed64x49', 'fixed64x50', 'fixed64x51', 'fixed64x52', 'fixed64x53', 'fixed64x54', 'fixed64x55', 'fixed64x56', 'fixed64x57', 'fixed64x58', 'fixed64x59', 'fixed64x60', 'fixed64x61', 'fixed64x62', 'fixed64x63', 'fixed64x64', 'fixed64x65', 'fixed64x66', 'fixed64x67', 'fixed64x68', 'fixed64x69', 'fixed64x70', 'fixed64x71', 'fixed64x72', 'fixed64x73', 'fixed64x74', 'fixed64x75', 'fixed64x76', 'fixed64x77', 'fixed64x78', 'fixed64x79', 'fixed64x80', 
    'fixed72x1', 'fixed72x2', 'fixed72x3', 'fixed72x4', 'fixed72x5', 'fixed72x6', 'fixed72x7', 'fixed72x8', 'fixed72x9', 'fixed72x10', 'fixed72x11', 'fixed72x12', 'fixed72x13', 'fixed72x14', 'fixed72x15', 'fixed72x16', 'fixed72x17', 'fixed72x18', 'fixed72x19', 'fixed72x20', 'fixed72x21', 'fixed72x22', 'fixed72x23', 'fixed72x24', 'fixed72x25', 'fixed72x26', 'fixed72x27', 'fixed72x28', 'fixed72x29', 'fixed72x30', 'fixed72x31', 'fixed72x32', 'fixed72x33', 'fixed72x34', 'fixed72x35', 'fixed72x36', 'fixed72x37', 'fixed72x38', 'fixed72x39', 'fixed72x40', 'fixed72x41', 'fixed72x42', 'fixed72x43', 'fixed72x44', 'fixed72x45', 'fixed72x46', 'fixed72x47', 'fixed72x48', 'fixed72x49', 'fixed72x50', 'fixed72x51', 'fixed72x52', 'fixed72x53', 'fixed72x54', 'fixed72x55', 'fixed72x56', 'fixed72x57', 'fixed72x58', 'fixed72x59', 'fixed72x60', 'fixed72x61', 'fixed72x62', 'fixed72x63', 'fixed72x64', 'fixed72x65', 'fixed72x66', 'fixed72x67', 'fixed72x68', 'fixed72x69', 'fixed72x70', 'fixed72x71', 'fixed72x72', 'fixed72x73', 'fixed72x74', 'fixed72x75', 'fixed72x76', 'fixed72x77', 'fixed72x78', 'fixed72x79', 'fixed72x80', 
    'fixed80x1', 'fixed80x2', 'fixed80x3', 'fixed80x4', 'fixed80x5', 'fixed80x6', 'fixed80x7', 'fixed80x8', 'fixed80x9', 'fixed80x10', 'fixed80x11', 'fixed80x12', 'fixed80x13', 'fixed80x14', 'fixed80x15', 'fixed80x16', 'fixed80x17', 'fixed80x18', 'fixed80x19', 'fixed80x20', 'fixed80x21', 'fixed80x22', 'fixed80x23', 'fixed80x24', 'fixed80x25', 'fixed80x26', 'fixed80x27', 'fixed80x28', 'fixed80x29', 'fixed80x30', 'fixed80x31', 'fixed80x32', 'fixed80x33', 'fixed80x34', 'fixed80x35', 'fixed80x36', 'fixed80x37', 'fixed80x38', 'fixed80x39', 'fixed80x40', 'fixed80x41', 'fixed80x42', 'fixed80x43', 'fixed80x44', 'fixed80x45', 'fixed80x46', 'fixed80x47', 'fixed80x48', 'fixed80x49', 'fixed80x50', 'fixed80x51', 'fixed80x52', 'fixed80x53', 'fixed80x54', 'fixed80x55', 'fixed80x56', 'fixed80x57', 'fixed80x58', 'fixed80x59', 'fixed80x60', 'fixed80x61', 'fixed80x62', 'fixed80x63', 'fixed80x64', 'fixed80x65', 'fixed80x66', 'fixed80x67', 'fixed80x68', 'fixed80x69', 'fixed80x70', 'fixed80x71', 'fixed80x72', 'fixed80x73', 'fixed80x74', 'fixed80x75', 'fixed80x76', 'fixed80x77', 'fixed80x78', 'fixed80x79', 'fixed80x80', 
    'fixed88x1', 'fixed88x2', 'fixed88x3', 'fixed88x4', 'fixed88x5', 'fixed88x6', 'fixed88x7', 'fixed88x8', 'fixed88x9', 'fixed88x10', 'fixed88x11', 'fixed88x12', 'fixed88x13', 'fixed88x14', 'fixed88x15', 'fixed88x16', 'fixed88x17', 'fixed88x18', 'fixed88x19', 'fixed88x20', 'fixed88x21', 'fixed88x22', 'fixed88x23', 'fixed88x24', 'fixed88x25', 'fixed88x26', 'fixed88x27', 'fixed88x28', 'fixed88x29', 'fixed88x30', 'fixed88x31', 'fixed88x32', 'fixed88x33', 'fixed88x34', 'fixed88x35', 'fixed88x36', 'fixed88x37', 'fixed88x38', 'fixed88x39', 'fixed88x40', 'fixed88x41', 'fixed88x42', 'fixed88x43', 'fixed88x44', 'fixed88x45', 'fixed88x46', 'fixed88x47', 'fixed88x48', 'fixed88x49', 'fixed88x50', 'fixed88x51', 'fixed88x52', 'fixed88x53', 'fixed88x54', 'fixed88x55', 'fixed88x56', 'fixed88x57', 'fixed88x58', 'fixed88x59', 'fixed88x60', 'fixed88x61', 'fixed88x62', 'fixed88x63', 'fixed88x64', 'fixed88x65', 'fixed88x66', 'fixed88x67', 'fixed88x68', 'fixed88x69', 'fixed88x70', 'fixed88x71', 'fixed88x72', 'fixed88x73', 'fixed88x74', 'fixed88x75', 'fixed88x76', 'fixed88x77', 'fixed88x78', 'fixed88x79', 'fixed88x80', 
    'fixed96x1', 'fixed96x2', 'fixed96x3', 'fixed96x4', 'fixed96x5', 'fixed96x6', 'fixed96x7', 'fixed96x8', 'fixed96x9', 'fixed96x10', 'fixed96x11', 'fixed96x12', 'fixed96x13', 'fixed96x14', 'fixed96x15', 'fixed96x16', 'fixed96x17', 'fixed96x18', 'fixed96x19', 'fixed96x20', 'fixed96x21', 'fixed96x22', 'fixed96x23', 'fixed96x24', 'fixed96x25', 'fixed96x26', 'fixed96x27', 'fixed96x28', 'fixed96x29', 'fixed96x30', 'fixed96x31', 'fixed96x32', 'fixed96x33', 'fixed96x34', 'fixed96x35', 'fixed96x36', 'fixed96x37', 'fixed96x38', 'fixed96x39', 'fixed96x40', 'fixed96x41', 'fixed96x42', 'fixed96x43', 'fixed96x44', 'fixed96x45', 'fixed96x46', 'fixed96x47', 'fixed96x48', 'fixed96x49', 'fixed96x50', 'fixed96x51', 'fixed96x52', 'fixed96x53', 'fixed96x54', 'fixed96x55', 'fixed96x56', 'fixed96x57', 'fixed96x58', 'fixed96x59', 'fixed96x60', 'fixed96x61', 'fixed96x62', 'fixed96x63', 'fixed96x64', 'fixed96x65', 'fixed96x66', 'fixed96x67', 'fixed96x68', 'fixed96x69', 'fixed96x70', 'fixed96x71', 'fixed96x72', 'fixed96x73', 'fixed96x74', 'fixed96x75', 'fixed96x76', 'fixed96x77', 'fixed96x78', 'fixed96x79', 'fixed96x80', 
    'fixed104x1', 'fixed104x2', 'fixed104x3', 'fixed104x4', 'fixed104x5', 'fixed104x6', 'fixed104x7', 'fixed104x8', 'fixed104x9', 'fixed104x10', 'fixed104x11', 'fixed104x12', 'fixed104x13', 'fixed104x14', 'fixed104x15', 'fixed104x16', 'fixed104x17', 'fixed104x18', 'fixed104x19', 'fixed104x20', 'fixed104x21', 'fixed104x22', 'fixed104x23', 'fixed104x24', 'fixed104x25', 'fixed104x26', 'fixed104x27', 'fixed104x28', 'fixed104x29', 'fixed104x30', 'fixed104x31', 'fixed104x32', 'fixed104x33', 'fixed104x34', 'fixed104x35', 'fixed104x36', 'fixed104x37', 'fixed104x38', 'fixed104x39', 'fixed104x40', 'fixed104x41', 'fixed104x42', 'fixed104x43', 'fixed104x44', 'fixed104x45', 'fixed104x46', 'fixed104x47', 'fixed104x48', 'fixed104x49', 'fixed104x50', 'fixed104x51', 'fixed104x52', 'fixed104x53', 'fixed104x54', 'fixed104x55', 'fixed104x56', 'fixed104x57', 'fixed104x58', 'fixed104x59', 'fixed104x60', 'fixed104x61', 'fixed104x62', 'fixed104x63', 'fixed104x64', 'fixed104x65', 'fixed104x66', 'fixed104x67', 'fixed104x68', 'fixed104x69', 'fixed104x70', 'fixed104x71', 'fixed104x72', 'fixed104x73', 'fixed104x74', 'fixed104x75', 'fixed104x76', 'fixed104x77', 'fixed104x78', 'fixed104x79', 'fixed104x80', 
    'fixed112x1', 'fixed112x2', 'fixed112x3', 'fixed112x4', 'fixed112x5', 'fixed112x6', 'fixed112x7', 'fixed112x8', 'fixed112x9', 'fixed112x10', 'fixed112x11', 'fixed112x12', 'fixed112x13', 'fixed112x14', 'fixed112x15', 'fixed112x16', 'fixed112x17', 'fixed112x18', 'fixed112x19', 'fixed112x20', 'fixed112x21', 'fixed112x22', 'fixed112x23', 'fixed112x24', 'fixed112x25', 'fixed112x26', 'fixed112x27', 'fixed112x28', 'fixed112x29', 'fixed112x30', 'fixed112x31', 'fixed112x32', 'fixed112x33', 'fixed112x34', 'fixed112x35', 'fixed112x36', 'fixed112x37', 'fixed112x38', 'fixed112x39', 'fixed112x40', 'fixed112x41', 'fixed112x42', 'fixed112x43', 'fixed112x44', 'fixed112x45', 'fixed112x46', 'fixed112x47', 'fixed112x48', 'fixed112x49', 'fixed112x50', 'fixed112x51', 'fixed112x52', 'fixed112x53', 'fixed112x54', 'fixed112x55', 'fixed112x56', 'fixed112x57', 'fixed112x58', 'fixed112x59', 'fixed112x60', 'fixed112x61', 'fixed112x62', 'fixed112x63', 'fixed112x64', 'fixed112x65', 'fixed112x66', 'fixed112x67', 'fixed112x68', 'fixed112x69', 'fixed112x70', 'fixed112x71', 'fixed112x72', 'fixed112x73', 'fixed112x74', 'fixed112x75', 'fixed112x76', 'fixed112x77', 'fixed112x78', 'fixed112x79', 'fixed112x80', 
    'fixed120x1', 'fixed120x2', 'fixed120x3', 'fixed120x4', 'fixed120x5', 'fixed120x6', 'fixed120x7', 'fixed120x8', 'fixed120x9', 'fixed120x10', 'fixed120x11', 'fixed120x12', 'fixed120x13', 'fixed120x14', 'fixed120x15', 'fixed120x16', 'fixed120x17', 'fixed120x18', 'fixed120x19', 'fixed120x20', 'fixed120x21', 'fixed120x22', 'fixed120x23', 'fixed120x24', 'fixed120x25', 'fixed120x26', 'fixed120x27', 'fixed120x28', 'fixed120x29', 'fixed120x30', 'fixed120x31', 'fixed120x32', 'fixed120x33', 'fixed120x34', 'fixed120x35', 'fixed120x36', 'fixed120x37', 'fixed120x38', 'fixed120x39', 'fixed120x40', 'fixed120x41', 'fixed120x42', 'fixed120x43', 'fixed120x44', 'fixed120x45', 'fixed120x46', 'fixed120x47', 'fixed120x48', 'fixed120x49', 'fixed120x50', 'fixed120x51', 'fixed120x52', 'fixed120x53', 'fixed120x54', 'fixed120x55', 'fixed120x56', 'fixed120x57', 'fixed120x58', 'fixed120x59', 'fixed120x60', 'fixed120x61', 'fixed120x62', 'fixed120x63', 'fixed120x64', 'fixed120x65', 'fixed120x66', 'fixed120x67', 'fixed120x68', 'fixed120x69', 'fixed120x70', 'fixed120x71', 'fixed120x72', 'fixed120x73', 'fixed120x74', 'fixed120x75', 'fixed120x76', 'fixed120x77', 'fixed120x78', 'fixed120x79', 'fixed120x80', 
    'fixed128x1', 'fixed128x2', 'fixed128x3', 'fixed128x4', 'fixed128x5', 'fixed128x6', 'fixed128x7', 'fixed128x8', 'fixed128x9', 'fixed128x10', 'fixed128x11', 'fixed128x12', 'fixed128x13', 'fixed128x14', 'fixed128x15', 'fixed128x16', 'fixed128x17', 'fixed128x18', 'fixed128x19', 'fixed128x20', 'fixed128x21', 'fixed128x22', 'fixed128x23', 'fixed128x24', 'fixed128x25', 'fixed128x26', 'fixed128x27', 'fixed128x28', 'fixed128x29', 'fixed128x30', 'fixed128x31', 'fixed128x32', 'fixed128x33', 'fixed128x34', 'fixed128x35', 'fixed128x36', 'fixed128x37', 'fixed128x38', 'fixed128x39', 'fixed128x40', 'fixed128x41', 'fixed128x42', 'fixed128x43', 'fixed128x44', 'fixed128x45', 'fixed128x46', 'fixed128x47', 'fixed128x48', 'fixed128x49', 'fixed128x50', 'fixed128x51', 'fixed128x52', 'fixed128x53', 'fixed128x54', 'fixed128x55', 'fixed128x56', 'fixed128x57', 'fixed128x58', 'fixed128x59', 'fixed128x60', 'fixed128x61', 'fixed128x62', 'fixed128x63', 'fixed128x64', 'fixed128x65', 'fixed128x66', 'fixed128x67', 'fixed128x68', 'fixed128x69', 'fixed128x70', 'fixed128x71', 'fixed128x72', 'fixed128x73', 'fixed128x74', 'fixed128x75', 'fixed128x76', 'fixed128x77', 'fixed128x78', 'fixed128x79', 'fixed128x80', 
    'fixed136x1', 'fixed136x2', 'fixed136x3', 'fixed136x4', 'fixed136x5', 'fixed136x6', 'fixed136x7', 'fixed136x8', 'fixed136x9', 'fixed136x10', 'fixed136x11', 'fixed136x12', 'fixed136x13', 'fixed136x14', 'fixed136x15', 'fixed136x16', 'fixed136x17', 'fixed136x18', 'fixed136x19', 'fixed136x20', 'fixed136x21', 'fixed136x22', 'fixed136x23', 'fixed136x24', 'fixed136x25', 'fixed136x26', 'fixed136x27', 'fixed136x28', 'fixed136x29', 'fixed136x30', 'fixed136x31', 'fixed136x32', 'fixed136x33', 'fixed136x34', 'fixed136x35', 'fixed136x36', 'fixed136x37', 'fixed136x38', 'fixed136x39', 'fixed136x40', 'fixed136x41', 'fixed136x42', 'fixed136x43', 'fixed136x44', 'fixed136x45', 'fixed136x46', 'fixed136x47', 'fixed136x48', 'fixed136x49', 'fixed136x50', 'fixed136x51', 'fixed136x52', 'fixed136x53', 'fixed136x54', 'fixed136x55', 'fixed136x56', 'fixed136x57', 'fixed136x58', 'fixed136x59', 'fixed136x60', 'fixed136x61', 'fixed136x62', 'fixed136x63', 'fixed136x64', 'fixed136x65', 'fixed136x66', 'fixed136x67', 'fixed136x68', 'fixed136x69', 'fixed136x70', 'fixed136x71', 'fixed136x72', 'fixed136x73', 'fixed136x74', 'fixed136x75', 'fixed136x76', 'fixed136x77', 'fixed136x78', 'fixed136x79', 'fixed136x80', 
    'fixed144x1', 'fixed144x2', 'fixed144x3', 'fixed144x4', 'fixed144x5', 'fixed144x6', 'fixed144x7', 'fixed144x8', 'fixed144x9', 'fixed144x10', 'fixed144x11', 'fixed144x12', 'fixed144x13', 'fixed144x14', 'fixed144x15', 'fixed144x16', 'fixed144x17', 'fixed144x18', 'fixed144x19', 'fixed144x20', 'fixed144x21', 'fixed144x22', 'fixed144x23', 'fixed144x24', 'fixed144x25', 'fixed144x26', 'fixed144x27', 'fixed144x28', 'fixed144x29', 'fixed144x30', 'fixed144x31', 'fixed144x32', 'fixed144x33', 'fixed144x34', 'fixed144x35', 'fixed144x36', 'fixed144x37', 'fixed144x38', 'fixed144x39', 'fixed144x40', 'fixed144x41', 'fixed144x42', 'fixed144x43', 'fixed144x44', 'fixed144x45', 'fixed144x46', 'fixed144x47', 'fixed144x48', 'fixed144x49', 'fixed144x50', 'fixed144x51', 'fixed144x52', 'fixed144x53', 'fixed144x54', 'fixed144x55', 'fixed144x56', 'fixed144x57', 'fixed144x58', 'fixed144x59', 'fixed144x60', 'fixed144x61', 'fixed144x62', 'fixed144x63', 'fixed144x64', 'fixed144x65', 'fixed144x66', 'fixed144x67', 'fixed144x68', 'fixed144x69', 'fixed144x70', 'fixed144x71', 'fixed144x72', 'fixed144x73', 'fixed144x74', 'fixed144x75', 'fixed144x76', 'fixed144x77', 'fixed144x78', 'fixed144x79', 'fixed144x80', 
    'fixed152x1', 'fixed152x2', 'fixed152x3', 'fixed152x4', 'fixed152x5', 'fixed152x6', 'fixed152x7', 'fixed152x8', 'fixed152x9', 'fixed152x10', 'fixed152x11', 'fixed152x12', 'fixed152x13', 'fixed152x14', 'fixed152x15', 'fixed152x16', 'fixed152x17', 'fixed152x18', 'fixed152x19', 'fixed152x20', 'fixed152x21', 'fixed152x22', 'fixed152x23', 'fixed152x24', 'fixed152x25', 'fixed152x26', 'fixed152x27', 'fixed152x28', 'fixed152x29', 'fixed152x30', 'fixed152x31', 'fixed152x32', 'fixed152x33', 'fixed152x34', 'fixed152x35', 'fixed152x36', 'fixed152x37', 'fixed152x38', 'fixed152x39', 'fixed152x40', 'fixed152x41', 'fixed152x42', 'fixed152x43', 'fixed152x44', 'fixed152x45', 'fixed152x46', 'fixed152x47', 'fixed152x48', 'fixed152x49', 'fixed152x50', 'fixed152x51', 'fixed152x52', 'fixed152x53', 'fixed152x54', 'fixed152x55', 'fixed152x56', 'fixed152x57', 'fixed152x58', 'fixed152x59', 'fixed152x60', 'fixed152x61', 'fixed152x62', 'fixed152x63', 'fixed152x64', 'fixed152x65', 'fixed152x66', 'fixed152x67', 'fixed152x68', 'fixed152x69', 'fixed152x70', 'fixed152x71', 'fixed152x72', 'fixed152x73', 'fixed152x74', 'fixed152x75', 'fixed152x76', 'fixed152x77', 'fixed152x78', 'fixed152x79', 'fixed152x80', 
    'fixed160x1', 'fixed160x2', 'fixed160x3', 'fixed160x4', 'fixed160x5', 'fixed160x6', 'fixed160x7', 'fixed160x8', 'fixed160x9', 'fixed160x10', 'fixed160x11', 'fixed160x12', 'fixed160x13', 'fixed160x14', 'fixed160x15', 'fixed160x16', 'fixed160x17', 'fixed160x18', 'fixed160x19', 'fixed160x20', 'fixed160x21', 'fixed160x22', 'fixed160x23', 'fixed160x24', 'fixed160x25', 'fixed160x26', 'fixed160x27', 'fixed160x28', 'fixed160x29', 'fixed160x30', 'fixed160x31', 'fixed160x32', 'fixed160x33', 'fixed160x34', 'fixed160x35', 'fixed160x36', 'fixed160x37', 'fixed160x38', 'fixed160x39', 'fixed160x40', 'fixed160x41', 'fixed160x42', 'fixed160x43', 'fixed160x44', 'fixed160x45', 'fixed160x46', 'fixed160x47', 'fixed160x48', 'fixed160x49', 'fixed160x50', 'fixed160x51', 'fixed160x52', 'fixed160x53', 'fixed160x54', 'fixed160x55', 'fixed160x56', 'fixed160x57', 'fixed160x58', 'fixed160x59', 'fixed160x60', 'fixed160x61', 'fixed160x62', 'fixed160x63', 'fixed160x64', 'fixed160x65', 'fixed160x66', 'fixed160x67', 'fixed160x68', 'fixed160x69', 'fixed160x70', 'fixed160x71', 'fixed160x72', 'fixed160x73', 'fixed160x74', 'fixed160x75', 'fixed160x76', 'fixed160x77', 'fixed160x78', 'fixed160x79', 'fixed160x80', 
    'fixed168x1', 'fixed168x2', 'fixed168x3', 'fixed168x4', 'fixed168x5', 'fixed168x6', 'fixed168x7', 'fixed168x8', 'fixed168x9', 'fixed168x10', 'fixed168x11', 'fixed168x12', 'fixed168x13', 'fixed168x14', 'fixed168x15', 'fixed168x16', 'fixed168x17', 'fixed168x18', 'fixed168x19', 'fixed168x20', 'fixed168x21', 'fixed168x22', 'fixed168x23', 'fixed168x24', 'fixed168x25', 'fixed168x26', 'fixed168x27', 'fixed168x28', 'fixed168x29', 'fixed168x30', 'fixed168x31', 'fixed168x32', 'fixed168x33', 'fixed168x34', 'fixed168x35', 'fixed168x36', 'fixed168x37', 'fixed168x38', 'fixed168x39', 'fixed168x40', 'fixed168x41', 'fixed168x42', 'fixed168x43', 'fixed168x44', 'fixed168x45', 'fixed168x46', 'fixed168x47', 'fixed168x48', 'fixed168x49', 'fixed168x50', 'fixed168x51', 'fixed168x52', 'fixed168x53', 'fixed168x54', 'fixed168x55', 'fixed168x56', 'fixed168x57', 'fixed168x58', 'fixed168x59', 'fixed168x60', 'fixed168x61', 'fixed168x62', 'fixed168x63', 'fixed168x64', 'fixed168x65', 'fixed168x66', 'fixed168x67', 'fixed168x68', 'fixed168x69', 'fixed168x70', 'fixed168x71', 'fixed168x72', 'fixed168x73', 'fixed168x74', 'fixed168x75', 'fixed168x76', 'fixed168x77', 'fixed168x78', 'fixed168x79', 'fixed168x80', 
    'fixed176x1', 'fixed176x2', 'fixed176x3', 'fixed176x4', 'fixed176x5', 'fixed176x6', 'fixed176x7', 'fixed176x8', 'fixed176x9', 'fixed176x10', 'fixed176x11', 'fixed176x12', 'fixed176x13', 'fixed176x14', 'fixed176x15', 'fixed176x16', 'fixed176x17', 'fixed176x18', 'fixed176x19', 'fixed176x20', 'fixed176x21', 'fixed176x22', 'fixed176x23', 'fixed176x24', 'fixed176x25', 'fixed176x26', 'fixed176x27', 'fixed176x28', 'fixed176x29', 'fixed176x30', 'fixed176x31', 'fixed176x32', 'fixed176x33', 'fixed176x34', 'fixed176x35', 'fixed176x36', 'fixed176x37', 'fixed176x38', 'fixed176x39', 'fixed176x40', 'fixed176x41', 'fixed176x42', 'fixed176x43', 'fixed176x44', 'fixed176x45', 'fixed176x46', 'fixed176x47', 'fixed176x48', 'fixed176x49', 'fixed176x50', 'fixed176x51', 'fixed176x52', 'fixed176x53', 'fixed176x54', 'fixed176x55', 'fixed176x56', 'fixed176x57', 'fixed176x58', 'fixed176x59', 'fixed176x60', 'fixed176x61', 'fixed176x62', 'fixed176x63', 'fixed176x64', 'fixed176x65', 'fixed176x66', 'fixed176x67', 'fixed176x68', 'fixed176x69', 'fixed176x70', 'fixed176x71', 'fixed176x72', 'fixed176x73', 'fixed176x74', 'fixed176x75', 'fixed176x76', 'fixed176x77', 'fixed176x78', 'fixed176x79', 'fixed176x80', 
    'fixed184x1', 'fixed184x2', 'fixed184x3', 'fixed184x4', 'fixed184x5', 'fixed184x6', 'fixed184x7', 'fixed184x8', 'fixed184x9', 'fixed184x10', 'fixed184x11', 'fixed184x12', 'fixed184x13', 'fixed184x14', 'fixed184x15', 'fixed184x16', 'fixed184x17', 'fixed184x18', 'fixed184x19', 'fixed184x20', 'fixed184x21', 'fixed184x22', 'fixed184x23', 'fixed184x24', 'fixed184x25', 'fixed184x26', 'fixed184x27', 'fixed184x28', 'fixed184x29', 'fixed184x30', 'fixed184x31', 'fixed184x32', 'fixed184x33', 'fixed184x34', 'fixed184x35', 'fixed184x36', 'fixed184x37', 'fixed184x38', 'fixed184x39', 'fixed184x40', 'fixed184x41', 'fixed184x42', 'fixed184x43', 'fixed184x44', 'fixed184x45', 'fixed184x46', 'fixed184x47', 'fixed184x48', 'fixed184x49', 'fixed184x50', 'fixed184x51', 'fixed184x52', 'fixed184x53', 'fixed184x54', 'fixed184x55', 'fixed184x56', 'fixed184x57', 'fixed184x58', 'fixed184x59', 'fixed184x60', 'fixed184x61', 'fixed184x62', 'fixed184x63', 'fixed184x64', 'fixed184x65', 'fixed184x66', 'fixed184x67', 'fixed184x68', 'fixed184x69', 'fixed184x70', 'fixed184x71', 'fixed184x72', 'fixed184x73', 'fixed184x74', 'fixed184x75', 'fixed184x76', 'fixed184x77', 'fixed184x78', 'fixed184x79', 'fixed184x80', 
    'fixed192x1', 'fixed192x2', 'fixed192x3', 'fixed192x4', 'fixed192x5', 'fixed192x6', 'fixed192x7', 'fixed192x8', 'fixed192x9', 'fixed192x10', 'fixed192x11', 'fixed192x12', 'fixed192x13', 'fixed192x14', 'fixed192x15', 'fixed192x16', 'fixed192x17', 'fixed192x18', 'fixed192x19', 'fixed192x20', 'fixed192x21', 'fixed192x22', 'fixed192x23', 'fixed192x24', 'fixed192x25', 'fixed192x26', 'fixed192x27', 'fixed192x28', 'fixed192x29', 'fixed192x30', 'fixed192x31', 'fixed192x32', 'fixed192x33', 'fixed192x34', 'fixed192x35', 'fixed192x36', 'fixed192x37', 'fixed192x38', 'fixed192x39', 'fixed192x40', 'fixed192x41', 'fixed192x42', 'fixed192x43', 'fixed192x44', 'fixed192x45', 'fixed192x46', 'fixed192x47', 'fixed192x48', 'fixed192x49', 'fixed192x50', 'fixed192x51', 'fixed192x52', 'fixed192x53', 'fixed192x54', 'fixed192x55', 'fixed192x56', 'fixed192x57', 'fixed192x58', 'fixed192x59', 'fixed192x60', 'fixed192x61', 'fixed192x62', 'fixed192x63', 'fixed192x64', 'fixed192x65', 'fixed192x66', 'fixed192x67', 'fixed192x68', 'fixed192x69', 'fixed192x70', 'fixed192x71', 'fixed192x72', 'fixed192x73', 'fixed192x74', 'fixed192x75', 'fixed192x76', 'fixed192x77', 'fixed192x78', 'fixed192x79', 'fixed192x80', 
    'fixed200x1', 'fixed200x2', 'fixed200x3', 'fixed200x4', 'fixed200x5', 'fixed200x6', 'fixed200x7', 'fixed200x8', 'fixed200x9', 'fixed200x10', 'fixed200x11', 'fixed200x12', 'fixed200x13', 'fixed200x14', 'fixed200x15', 'fixed200x16', 'fixed200x17', 'fixed200x18', 'fixed200x19', 'fixed200x20', 'fixed200x21', 'fixed200x22', 'fixed200x23', 'fixed200x24', 'fixed200x25', 'fixed200x26', 'fixed200x27', 'fixed200x28', 'fixed200x29', 'fixed200x30', 'fixed200x31', 'fixed200x32', 'fixed200x33', 'fixed200x34', 'fixed200x35', 'fixed200x36', 'fixed200x37', 'fixed200x38', 'fixed200x39', 'fixed200x40', 'fixed200x41', 'fixed200x42', 'fixed200x43', 'fixed200x44', 'fixed200x45', 'fixed200x46', 'fixed200x47', 'fixed200x48', 'fixed200x49', 'fixed200x50', 'fixed200x51', 'fixed200x52', 'fixed200x53', 'fixed200x54', 'fixed200x55', 'fixed200x56', 'fixed200x57', 'fixed200x58', 'fixed200x59', 'fixed200x60', 'fixed200x61', 'fixed200x62', 'fixed200x63', 'fixed200x64', 'fixed200x65', 'fixed200x66', 'fixed200x67', 'fixed200x68', 'fixed200x69', 'fixed200x70', 'fixed200x71', 'fixed200x72', 'fixed200x73', 'fixed200x74', 'fixed200x75', 'fixed200x76', 'fixed200x77', 'fixed200x78', 'fixed200x79', 'fixed200x80', 
    'fixed208x1', 'fixed208x2', 'fixed208x3', 'fixed208x4', 'fixed208x5', 'fixed208x6', 'fixed208x7', 'fixed208x8', 'fixed208x9', 'fixed208x10', 'fixed208x11', 'fixed208x12', 'fixed208x13', 'fixed208x14', 'fixed208x15', 'fixed208x16', 'fixed208x17', 'fixed208x18', 'fixed208x19', 'fixed208x20', 'fixed208x21', 'fixed208x22', 'fixed208x23', 'fixed208x24', 'fixed208x25', 'fixed208x26', 'fixed208x27', 'fixed208x28', 'fixed208x29', 'fixed208x30', 'fixed208x31', 'fixed208x32', 'fixed208x33', 'fixed208x34', 'fixed208x35', 'fixed208x36', 'fixed208x37', 'fixed208x38', 'fixed208x39', 'fixed208x40', 'fixed208x41', 'fixed208x42', 'fixed208x43', 'fixed208x44', 'fixed208x45', 'fixed208x46', 'fixed208x47', 'fixed208x48', 'fixed208x49', 'fixed208x50', 'fixed208x51', 'fixed208x52', 'fixed208x53', 'fixed208x54', 'fixed208x55', 'fixed208x56', 'fixed208x57', 'fixed208x58', 'fixed208x59', 'fixed208x60', 'fixed208x61', 'fixed208x62', 'fixed208x63', 'fixed208x64', 'fixed208x65', 'fixed208x66', 'fixed208x67', 'fixed208x68', 'fixed208x69', 'fixed208x70', 'fixed208x71', 'fixed208x72', 'fixed208x73', 'fixed208x74', 'fixed208x75', 'fixed208x76', 'fixed208x77', 'fixed208x78', 'fixed208x79', 'fixed208x80', 
    'fixed216x1', 'fixed216x2', 'fixed216x3', 'fixed216x4', 'fixed216x5', 'fixed216x6', 'fixed216x7', 'fixed216x8', 'fixed216x9', 'fixed216x10', 'fixed216x11', 'fixed216x12', 'fixed216x13', 'fixed216x14', 'fixed216x15', 'fixed216x16', 'fixed216x17', 'fixed216x18', 'fixed216x19', 'fixed216x20', 'fixed216x21', 'fixed216x22', 'fixed216x23', 'fixed216x24', 'fixed216x25', 'fixed216x26', 'fixed216x27', 'fixed216x28', 'fixed216x29', 'fixed216x30', 'fixed216x31', 'fixed216x32', 'fixed216x33', 'fixed216x34', 'fixed216x35', 'fixed216x36', 'fixed216x37', 'fixed216x38', 'fixed216x39', 'fixed216x40', 'fixed216x41', 'fixed216x42', 'fixed216x43', 'fixed216x44', 'fixed216x45', 'fixed216x46', 'fixed216x47', 'fixed216x48', 'fixed216x49', 'fixed216x50', 'fixed216x51', 'fixed216x52', 'fixed216x53', 'fixed216x54', 'fixed216x55', 'fixed216x56', 'fixed216x57', 'fixed216x58', 'fixed216x59', 'fixed216x60', 'fixed216x61', 'fixed216x62', 'fixed216x63', 'fixed216x64', 'fixed216x65', 'fixed216x66', 'fixed216x67', 'fixed216x68', 'fixed216x69', 'fixed216x70', 'fixed216x71', 'fixed216x72', 'fixed216x73', 'fixed216x74', 'fixed216x75', 'fixed216x76', 'fixed216x77', 'fixed216x78', 'fixed216x79', 'fixed216x80', 
    'fixed224x1', 'fixed224x2', 'fixed224x3', 'fixed224x4', 'fixed224x5', 'fixed224x6', 'fixed224x7', 'fixed224x8', 'fixed224x9', 'fixed224x10', 'fixed224x11', 'fixed224x12', 'fixed224x13', 'fixed224x14', 'fixed224x15', 'fixed224x16', 'fixed224x17', 'fixed224x18', 'fixed224x19', 'fixed224x20', 'fixed224x21', 'fixed224x22', 'fixed224x23', 'fixed224x24', 'fixed224x25', 'fixed224x26', 'fixed224x27', 'fixed224x28', 'fixed224x29', 'fixed224x30', 'fixed224x31', 'fixed224x32', 'fixed224x33', 'fixed224x34', 'fixed224x35', 'fixed224x36', 'fixed224x37', 'fixed224x38', 'fixed224x39', 'fixed224x40', 'fixed224x41', 'fixed224x42', 'fixed224x43', 'fixed224x44', 'fixed224x45', 'fixed224x46', 'fixed224x47', 'fixed224x48', 'fixed224x49', 'fixed224x50', 'fixed224x51', 'fixed224x52', 'fixed224x53', 'fixed224x54', 'fixed224x55', 'fixed224x56', 'fixed224x57', 'fixed224x58', 'fixed224x59', 'fixed224x60', 'fixed224x61', 'fixed224x62', 'fixed224x63', 'fixed224x64', 'fixed224x65', 'fixed224x66', 'fixed224x67', 'fixed224x68', 'fixed224x69', 'fixed224x70', 'fixed224x71', 'fixed224x72', 'fixed224x73', 'fixed224x74', 'fixed224x75', 'fixed224x76', 'fixed224x77', 'fixed224x78', 'fixed224x79', 'fixed224x80', 
    'fixed232x1', 'fixed232x2', 'fixed232x3', 'fixed232x4', 'fixed232x5', 'fixed232x6', 'fixed232x7', 'fixed232x8', 'fixed232x9', 'fixed232x10', 'fixed232x11', 'fixed232x12', 'fixed232x13', 'fixed232x14', 'fixed232x15', 'fixed232x16', 'fixed232x17', 'fixed232x18', 'fixed232x19', 'fixed232x20', 'fixed232x21', 'fixed232x22', 'fixed232x23', 'fixed232x24', 'fixed232x25', 'fixed232x26', 'fixed232x27', 'fixed232x28', 'fixed232x29', 'fixed232x30', 'fixed232x31', 'fixed232x32', 'fixed232x33', 'fixed232x34', 'fixed232x35', 'fixed232x36', 'fixed232x37', 'fixed232x38', 'fixed232x39', 'fixed232x40', 'fixed232x41', 'fixed232x42', 'fixed232x43', 'fixed232x44', 'fixed232x45', 'fixed232x46', 'fixed232x47', 'fixed232x48', 'fixed232x49', 'fixed232x50', 'fixed232x51', 'fixed232x52', 'fixed232x53', 'fixed232x54', 'fixed232x55', 'fixed232x56', 'fixed232x57', 'fixed232x58', 'fixed232x59', 'fixed232x60', 'fixed232x61', 'fixed232x62', 'fixed232x63', 'fixed232x64', 'fixed232x65', 'fixed232x66', 'fixed232x67', 'fixed232x68', 'fixed232x69', 'fixed232x70', 'fixed232x71', 'fixed232x72', 'fixed232x73', 'fixed232x74', 'fixed232x75', 'fixed232x76', 'fixed232x77', 'fixed232x78', 'fixed232x79', 'fixed232x80', 
    'fixed240x1', 'fixed240x2', 'fixed240x3', 'fixed240x4', 'fixed240x5', 'fixed240x6', 'fixed240x7', 'fixed240x8', 'fixed240x9', 'fixed240x10', 'fixed240x11', 'fixed240x12', 'fixed240x13', 'fixed240x14', 'fixed240x15', 'fixed240x16', 'fixed240x17', 'fixed240x18', 'fixed240x19', 'fixed240x20', 'fixed240x21', 'fixed240x22', 'fixed240x23', 'fixed240x24', 'fixed240x25', 'fixed240x26', 'fixed240x27', 'fixed240x28', 'fixed240x29', 'fixed240x30', 'fixed240x31', 'fixed240x32', 'fixed240x33', 'fixed240x34', 'fixed240x35', 'fixed240x36', 'fixed240x37', 'fixed240x38', 'fixed240x39', 'fixed240x40', 'fixed240x41', 'fixed240x42', 'fixed240x43', 'fixed240x44', 'fixed240x45', 'fixed240x46', 'fixed240x47', 'fixed240x48', 'fixed240x49', 'fixed240x50', 'fixed240x51', 'fixed240x52', 'fixed240x53', 'fixed240x54', 'fixed240x55', 'fixed240x56', 'fixed240x57', 'fixed240x58', 'fixed240x59', 'fixed240x60', 'fixed240x61', 'fixed240x62', 'fixed240x63', 'fixed240x64', 'fixed240x65', 'fixed240x66', 'fixed240x67', 'fixed240x68', 'fixed240x69', 'fixed240x70', 'fixed240x71', 'fixed240x72', 'fixed240x73', 'fixed240x74', 'fixed240x75', 'fixed240x76', 'fixed240x77', 'fixed240x78', 'fixed240x79', 'fixed240x80', 
    'fixed248x1', 'fixed248x2', 'fixed248x3', 'fixed248x4', 'fixed248x5', 'fixed248x6', 'fixed248x7', 'fixed248x8', 'fixed248x9', 'fixed248x10', 'fixed248x11', 'fixed248x12', 'fixed248x13', 'fixed248x14', 'fixed248x15', 'fixed248x16', 'fixed248x17', 'fixed248x18', 'fixed248x19', 'fixed248x20', 'fixed248x21', 'fixed248x22', 'fixed248x23', 'fixed248x24', 'fixed248x25', 'fixed248x26', 'fixed248x27', 'fixed248x28', 'fixed248x29', 'fixed248x30', 'fixed248x31', 'fixed248x32', 'fixed248x33', 'fixed248x34', 'fixed248x35', 'fixed248x36', 'fixed248x37', 'fixed248x38', 'fixed248x39', 'fixed248x40', 'fixed248x41', 'fixed248x42', 'fixed248x43', 'fixed248x44', 'fixed248x45', 'fixed248x46', 'fixed248x47', 'fixed248x48', 'fixed248x49', 'fixed248x50', 'fixed248x51', 'fixed248x52', 'fixed248x53', 'fixed248x54', 'fixed248x55', 'fixed248x56', 'fixed248x57', 'fixed248x58', 'fixed248x59', 'fixed248x60', 'fixed248x61', 'fixed248x62', 'fixed248x63', 'fixed248x64', 'fixed248x65', 'fixed248x66', 'fixed248x67', 'fixed248x68', 'fixed248x69', 'fixed248x70', 'fixed248x71', 'fixed248x72', 'fixed248x73', 'fixed248x74', 'fixed248x75', 'fixed248x76', 'fixed248x77', 'fixed248x78', 'fixed248x79', 'fixed248x80', 
    'fixed256x1', 'fixed256x2', 'fixed256x3', 'fixed256x4', 'fixed256x5', 'fixed256x6', 'fixed256x7', 'fixed256x8', 'fixed256x9', 'fixed256x10', 'fixed256x11', 'fixed256x12', 'fixed256x13', 'fixed256x14', 'fixed256x15', 'fixed256x16', 'fixed256x17', 'fixed256x18', 'fixed256x19', 'fixed256x20', 'fixed256x21', 'fixed256x22', 'fixed256x23', 'fixed256x24', 'fixed256x25', 'fixed256x26', 'fixed256x27', 'fixed256x28', 'fixed256x29', 'fixed256x30', 'fixed256x31', 'fixed256x32', 'fixed256x33', 'fixed256x34', 'fixed256x35', 'fixed256x36', 'fixed256x37', 'fixed256x38', 'fixed256x39', 'fixed256x40', 'fixed256x41', 'fixed256x42', 'fixed256x43', 'fixed256x44', 'fixed256x45', 'fixed256x46', 'fixed256x47', 'fixed256x48', 'fixed256x49', 'fixed256x50', 'fixed256x51', 'fixed256x52', 'fixed256x53', 'fixed256x54', 'fixed256x55', 'fixed256x56', 'fixed256x57', 'fixed256x58', 'fixed256x59', 'fixed256x60', 'fixed256x61', 'fixed256x62', 'fixed256x63', 'fixed256x64', 'fixed256x65', 'fixed256x66', 'fixed256x67', 'fixed256x68', 'fixed256x69', 'fixed256x70', 'fixed256x71', 'fixed256x72', 'fixed256x73', 'fixed256x74', 'fixed256x75', 'fixed256x76', 'fixed256x77', 'fixed256x78', 'fixed256x79', 'fixed256x80', 

    'ufixed8x1', 'ufixed8x2', 'ufixed8x3', 'ufixed8x4', 'ufixed8x5', 'ufixed8x6', 'ufixed8x7', 'ufixed8x8', 'ufixed8x9', 'ufixed8x10', 'ufixed8x11', 'ufixed8x12', 'ufixed8x13', 'ufixed8x14', 'ufixed8x15', 'ufixed8x16', 'ufixed8x17', 'ufixed8x18', 'ufixed8x19', 'ufixed8x20', 'ufixed8x21', 'ufixed8x22', 'ufixed8x23', 'ufixed8x24', 'ufixed8x25', 'ufixed8x26', 'ufixed8x27', 'ufixed8x28', 'ufixed8x29', 'ufixed8x30', 'ufixed8x31', 'ufixed8x32', 'ufixed8x33', 'ufixed8x34', 'ufixed8x35', 'ufixed8x36', 'ufixed8x37', 'ufixed8x38', 'ufixed8x39', 'ufixed8x40', 'ufixed8x41', 'ufixed8x42', 'ufixed8x43', 'ufixed8x44', 'ufixed8x45', 'ufixed8x46', 'ufixed8x47', 'ufixed8x48', 'ufixed8x49', 'ufixed8x50', 'ufixed8x51', 'ufixed8x52', 'ufixed8x53', 'ufixed8x54', 'ufixed8x55', 'ufixed8x56', 'ufixed8x57', 'ufixed8x58', 'ufixed8x59', 'ufixed8x60', 'ufixed8x61', 'ufixed8x62', 'ufixed8x63', 'ufixed8x64', 'ufixed8x65', 'ufixed8x66', 'ufixed8x67', 'ufixed8x68', 'ufixed8x69', 'ufixed8x70', 'ufixed8x71', 'ufixed8x72', 'ufixed8x73', 'ufixed8x74', 'ufixed8x75', 'ufixed8x76', 'ufixed8x77', 'ufixed8x78', 'ufixed8x79', 'ufixed8x80', 
    'ufixed16x1', 'ufixed16x2', 'ufixed16x3', 'ufixed16x4', 'ufixed16x5', 'ufixed16x6', 'ufixed16x7', 'ufixed16x8', 'ufixed16x9', 'ufixed16x10', 'ufixed16x11', 'ufixed16x12', 'ufixed16x13', 'ufixed16x14', 'ufixed16x15', 'ufixed16x16', 'ufixed16x17', 'ufixed16x18', 'ufixed16x19', 'ufixed16x20', 'ufixed16x21', 'ufixed16x22', 'ufixed16x23', 'ufixed16x24', 'ufixed16x25', 'ufixed16x26', 'ufixed16x27', 'ufixed16x28', 'ufixed16x29', 'ufixed16x30', 'ufixed16x31', 'ufixed16x32', 'ufixed16x33', 'ufixed16x34', 'ufixed16x35', 'ufixed16x36', 'ufixed16x37', 'ufixed16x38', 'ufixed16x39', 'ufixed16x40', 'ufixed16x41', 'ufixed16x42', 'ufixed16x43', 'ufixed16x44', 'ufixed16x45', 'ufixed16x46', 'ufixed16x47', 'ufixed16x48', 'ufixed16x49', 'ufixed16x50', 'ufixed16x51', 'ufixed16x52', 'ufixed16x53', 'ufixed16x54', 'ufixed16x55', 'ufixed16x56', 'ufixed16x57', 'ufixed16x58', 'ufixed16x59', 'ufixed16x60', 'ufixed16x61', 'ufixed16x62', 'ufixed16x63', 'ufixed16x64', 'ufixed16x65', 'ufixed16x66', 'ufixed16x67', 'ufixed16x68', 'ufixed16x69', 'ufixed16x70', 'ufixed16x71', 'ufixed16x72', 'ufixed16x73', 'ufixed16x74', 'ufixed16x75', 'ufixed16x76', 'ufixed16x77', 'ufixed16x78', 'ufixed16x79', 'ufixed16x80', 
    'ufixed24x1', 'ufixed24x2', 'ufixed24x3', 'ufixed24x4', 'ufixed24x5', 'ufixed24x6', 'ufixed24x7', 'ufixed24x8', 'ufixed24x9', 'ufixed24x10', 'ufixed24x11', 'ufixed24x12', 'ufixed24x13', 'ufixed24x14', 'ufixed24x15', 'ufixed24x16', 'ufixed24x17', 'ufixed24x18', 'ufixed24x19', 'ufixed24x20', 'ufixed24x21', 'ufixed24x22', 'ufixed24x23', 'ufixed24x24', 'ufixed24x25', 'ufixed24x26', 'ufixed24x27', 'ufixed24x28', 'ufixed24x29', 'ufixed24x30', 'ufixed24x31', 'ufixed24x32', 'ufixed24x33', 'ufixed24x34', 'ufixed24x35', 'ufixed24x36', 'ufixed24x37', 'ufixed24x38', 'ufixed24x39', 'ufixed24x40', 'ufixed24x41', 'ufixed24x42', 'ufixed24x43', 'ufixed24x44', 'ufixed24x45', 'ufixed24x46', 'ufixed24x47', 'ufixed24x48', 'ufixed24x49', 'ufixed24x50', 'ufixed24x51', 'ufixed24x52', 'ufixed24x53', 'ufixed24x54', 'ufixed24x55', 'ufixed24x56', 'ufixed24x57', 'ufixed24x58', 'ufixed24x59', 'ufixed24x60', 'ufixed24x61', 'ufixed24x62', 'ufixed24x63', 'ufixed24x64', 'ufixed24x65', 'ufixed24x66', 'ufixed24x67', 'ufixed24x68', 'ufixed24x69', 'ufixed24x70', 'ufixed24x71', 'ufixed24x72', 'ufixed24x73', 'ufixed24x74', 'ufixed24x75', 'ufixed24x76', 'ufixed24x77', 'ufixed24x78', 'ufixed24x79', 'ufixed24x80', 
    'ufixed32x1', 'ufixed32x2', 'ufixed32x3', 'ufixed32x4', 'ufixed32x5', 'ufixed32x6', 'ufixed32x7', 'ufixed32x8', 'ufixed32x9', 'ufixed32x10', 'ufixed32x11', 'ufixed32x12', 'ufixed32x13', 'ufixed32x14', 'ufixed32x15', 'ufixed32x16', 'ufixed32x17', 'ufixed32x18', 'ufixed32x19', 'ufixed32x20', 'ufixed32x21', 'ufixed32x22', 'ufixed32x23', 'ufixed32x24', 'ufixed32x25', 'ufixed32x26', 'ufixed32x27', 'ufixed32x28', 'ufixed32x29', 'ufixed32x30', 'ufixed32x31', 'ufixed32x32', 'ufixed32x33', 'ufixed32x34', 'ufixed32x35', 'ufixed32x36', 'ufixed32x37', 'ufixed32x38', 'ufixed32x39', 'ufixed32x40', 'ufixed32x41', 'ufixed32x42', 'ufixed32x43', 'ufixed32x44', 'ufixed32x45', 'ufixed32x46', 'ufixed32x47', 'ufixed32x48', 'ufixed32x49', 'ufixed32x50', 'ufixed32x51', 'ufixed32x52', 'ufixed32x53', 'ufixed32x54', 'ufixed32x55', 'ufixed32x56', 'ufixed32x57', 'ufixed32x58', 'ufixed32x59', 'ufixed32x60', 'ufixed32x61', 'ufixed32x62', 'ufixed32x63', 'ufixed32x64', 'ufixed32x65', 'ufixed32x66', 'ufixed32x67', 'ufixed32x68', 'ufixed32x69', 'ufixed32x70', 'ufixed32x71', 'ufixed32x72', 'ufixed32x73', 'ufixed32x74', 'ufixed32x75', 'ufixed32x76', 'ufixed32x77', 'ufixed32x78', 'ufixed32x79', 'ufixed32x80', 
    'ufixed40x1', 'ufixed40x2', 'ufixed40x3', 'ufixed40x4', 'ufixed40x5', 'ufixed40x6', 'ufixed40x7', 'ufixed40x8', 'ufixed40x9', 'ufixed40x10', 'ufixed40x11', 'ufixed40x12', 'ufixed40x13', 'ufixed40x14', 'ufixed40x15', 'ufixed40x16', 'ufixed40x17', 'ufixed40x18', 'ufixed40x19', 'ufixed40x20', 'ufixed40x21', 'ufixed40x22', 'ufixed40x23', 'ufixed40x24', 'ufixed40x25', 'ufixed40x26', 'ufixed40x27', 'ufixed40x28', 'ufixed40x29', 'ufixed40x30', 'ufixed40x31', 'ufixed40x32', 'ufixed40x33', 'ufixed40x34', 'ufixed40x35', 'ufixed40x36', 'ufixed40x37', 'ufixed40x38', 'ufixed40x39', 'ufixed40x40', 'ufixed40x41', 'ufixed40x42', 'ufixed40x43', 'ufixed40x44', 'ufixed40x45', 'ufixed40x46', 'ufixed40x47', 'ufixed40x48', 'ufixed40x49', 'ufixed40x50', 'ufixed40x51', 'ufixed40x52', 'ufixed40x53', 'ufixed40x54', 'ufixed40x55', 'ufixed40x56', 'ufixed40x57', 'ufixed40x58', 'ufixed40x59', 'ufixed40x60', 'ufixed40x61', 'ufixed40x62', 'ufixed40x63', 'ufixed40x64', 'ufixed40x65', 'ufixed40x66', 'ufixed40x67', 'ufixed40x68', 'ufixed40x69', 'ufixed40x70', 'ufixed40x71', 'ufixed40x72', 'ufixed40x73', 'ufixed40x74', 'ufixed40x75', 'ufixed40x76', 'ufixed40x77', 'ufixed40x78', 'ufixed40x79', 'ufixed40x80', 
    'ufixed48x1', 'ufixed48x2', 'ufixed48x3', 'ufixed48x4', 'ufixed48x5', 'ufixed48x6', 'ufixed48x7', 'ufixed48x8', 'ufixed48x9', 'ufixed48x10', 'ufixed48x11', 'ufixed48x12', 'ufixed48x13', 'ufixed48x14', 'ufixed48x15', 'ufixed48x16', 'ufixed48x17', 'ufixed48x18', 'ufixed48x19', 'ufixed48x20', 'ufixed48x21', 'ufixed48x22', 'ufixed48x23', 'ufixed48x24', 'ufixed48x25', 'ufixed48x26', 'ufixed48x27', 'ufixed48x28', 'ufixed48x29', 'ufixed48x30', 'ufixed48x31', 'ufixed48x32', 'ufixed48x33', 'ufixed48x34', 'ufixed48x35', 'ufixed48x36', 'ufixed48x37', 'ufixed48x38', 'ufixed48x39', 'ufixed48x40', 'ufixed48x41', 'ufixed48x42', 'ufixed48x43', 'ufixed48x44', 'ufixed48x45', 'ufixed48x46', 'ufixed48x47', 'ufixed48x48', 'ufixed48x49', 'ufixed48x50', 'ufixed48x51', 'ufixed48x52', 'ufixed48x53', 'ufixed48x54', 'ufixed48x55', 'ufixed48x56', 'ufixed48x57', 'ufixed48x58', 'ufixed48x59', 'ufixed48x60', 'ufixed48x61', 'ufixed48x62', 'ufixed48x63', 'ufixed48x64', 'ufixed48x65', 'ufixed48x66', 'ufixed48x67', 'ufixed48x68', 'ufixed48x69', 'ufixed48x70', 'ufixed48x71', 'ufixed48x72', 'ufixed48x73', 'ufixed48x74', 'ufixed48x75', 'ufixed48x76', 'ufixed48x77', 'ufixed48x78', 'ufixed48x79', 'ufixed48x80', 
    'ufixed56x1', 'ufixed56x2', 'ufixed56x3', 'ufixed56x4', 'ufixed56x5', 'ufixed56x6', 'ufixed56x7', 'ufixed56x8', 'ufixed56x9', 'ufixed56x10', 'ufixed56x11', 'ufixed56x12', 'ufixed56x13', 'ufixed56x14', 'ufixed56x15', 'ufixed56x16', 'ufixed56x17', 'ufixed56x18', 'ufixed56x19', 'ufixed56x20', 'ufixed56x21', 'ufixed56x22', 'ufixed56x23', 'ufixed56x24', 'ufixed56x25', 'ufixed56x26', 'ufixed56x27', 'ufixed56x28', 'ufixed56x29', 'ufixed56x30', 'ufixed56x31', 'ufixed56x32', 'ufixed56x33', 'ufixed56x34', 'ufixed56x35', 'ufixed56x36', 'ufixed56x37', 'ufixed56x38', 'ufixed56x39', 'ufixed56x40', 'ufixed56x41', 'ufixed56x42', 'ufixed56x43', 'ufixed56x44', 'ufixed56x45', 'ufixed56x46', 'ufixed56x47', 'ufixed56x48', 'ufixed56x49', 'ufixed56x50', 'ufixed56x51', 'ufixed56x52', 'ufixed56x53', 'ufixed56x54', 'ufixed56x55', 'ufixed56x56', 'ufixed56x57', 'ufixed56x58', 'ufixed56x59', 'ufixed56x60', 'ufixed56x61', 'ufixed56x62', 'ufixed56x63', 'ufixed56x64', 'ufixed56x65', 'ufixed56x66', 'ufixed56x67', 'ufixed56x68', 'ufixed56x69', 'ufixed56x70', 'ufixed56x71', 'ufixed56x72', 'ufixed56x73', 'ufixed56x74', 'ufixed56x75', 'ufixed56x76', 'ufixed56x77', 'ufixed56x78', 'ufixed56x79', 'ufixed56x80', 
    'ufixed64x1', 'ufixed64x2', 'ufixed64x3', 'ufixed64x4', 'ufixed64x5', 'ufixed64x6', 'ufixed64x7', 'ufixed64x8', 'ufixed64x9', 'ufixed64x10', 'ufixed64x11', 'ufixed64x12', 'ufixed64x13', 'ufixed64x14', 'ufixed64x15', 'ufixed64x16', 'ufixed64x17', 'ufixed64x18', 'ufixed64x19', 'ufixed64x20', 'ufixed64x21', 'ufixed64x22', 'ufixed64x23', 'ufixed64x24', 'ufixed64x25', 'ufixed64x26', 'ufixed64x27', 'ufixed64x28', 'ufixed64x29', 'ufixed64x30', 'ufixed64x31', 'ufixed64x32', 'ufixed64x33', 'ufixed64x34', 'ufixed64x35', 'ufixed64x36', 'ufixed64x37', 'ufixed64x38', 'ufixed64x39', 'ufixed64x40', 'ufixed64x41', 'ufixed64x42', 'ufixed64x43', 'ufixed64x44', 'ufixed64x45', 'ufixed64x46', 'ufixed64x47', 'ufixed64x48', 'ufixed64x49', 'ufixed64x50', 'ufixed64x51', 'ufixed64x52', 'ufixed64x53', 'ufixed64x54', 'ufixed64x55', 'ufixed64x56', 'ufixed64x57', 'ufixed64x58', 'ufixed64x59', 'ufixed64x60', 'ufixed64x61', 'ufixed64x62', 'ufixed64x63', 'ufixed64x64', 'ufixed64x65', 'ufixed64x66', 'ufixed64x67', 'ufixed64x68', 'ufixed64x69', 'ufixed64x70', 'ufixed64x71', 'ufixed64x72', 'ufixed64x73', 'ufixed64x74', 'ufixed64x75', 'ufixed64x76', 'ufixed64x77', 'ufixed64x78', 'ufixed64x79', 'ufixed64x80', 
    'ufixed72x1', 'ufixed72x2', 'ufixed72x3', 'ufixed72x4', 'ufixed72x5', 'ufixed72x6', 'ufixed72x7', 'ufixed72x8', 'ufixed72x9', 'ufixed72x10', 'ufixed72x11', 'ufixed72x12', 'ufixed72x13', 'ufixed72x14', 'ufixed72x15', 'ufixed72x16', 'ufixed72x17', 'ufixed72x18', 'ufixed72x19', 'ufixed72x20', 'ufixed72x21', 'ufixed72x22', 'ufixed72x23', 'ufixed72x24', 'ufixed72x25', 'ufixed72x26', 'ufixed72x27', 'ufixed72x28', 'ufixed72x29', 'ufixed72x30', 'ufixed72x31', 'ufixed72x32', 'ufixed72x33', 'ufixed72x34', 'ufixed72x35', 'ufixed72x36', 'ufixed72x37', 'ufixed72x38', 'ufixed72x39', 'ufixed72x40', 'ufixed72x41', 'ufixed72x42', 'ufixed72x43', 'ufixed72x44', 'ufixed72x45', 'ufixed72x46', 'ufixed72x47', 'ufixed72x48', 'ufixed72x49', 'ufixed72x50', 'ufixed72x51', 'ufixed72x52', 'ufixed72x53', 'ufixed72x54', 'ufixed72x55', 'ufixed72x56', 'ufixed72x57', 'ufixed72x58', 'ufixed72x59', 'ufixed72x60', 'ufixed72x61', 'ufixed72x62', 'ufixed72x63', 'ufixed72x64', 'ufixed72x65', 'ufixed72x66', 'ufixed72x67', 'ufixed72x68', 'ufixed72x69', 'ufixed72x70', 'ufixed72x71', 'ufixed72x72', 'ufixed72x73', 'ufixed72x74', 'ufixed72x75', 'ufixed72x76', 'ufixed72x77', 'ufixed72x78', 'ufixed72x79', 'ufixed72x80', 
    'ufixed80x1', 'ufixed80x2', 'ufixed80x3', 'ufixed80x4', 'ufixed80x5', 'ufixed80x6', 'ufixed80x7', 'ufixed80x8', 'ufixed80x9', 'ufixed80x10', 'ufixed80x11', 'ufixed80x12', 'ufixed80x13', 'ufixed80x14', 'ufixed80x15', 'ufixed80x16', 'ufixed80x17', 'ufixed80x18', 'ufixed80x19', 'ufixed80x20', 'ufixed80x21', 'ufixed80x22', 'ufixed80x23', 'ufixed80x24', 'ufixed80x25', 'ufixed80x26', 'ufixed80x27', 'ufixed80x28', 'ufixed80x29', 'ufixed80x30', 'ufixed80x31', 'ufixed80x32', 'ufixed80x33', 'ufixed80x34', 'ufixed80x35', 'ufixed80x36', 'ufixed80x37', 'ufixed80x38', 'ufixed80x39', 'ufixed80x40', 'ufixed80x41', 'ufixed80x42', 'ufixed80x43', 'ufixed80x44', 'ufixed80x45', 'ufixed80x46', 'ufixed80x47', 'ufixed80x48', 'ufixed80x49', 'ufixed80x50', 'ufixed80x51', 'ufixed80x52', 'ufixed80x53', 'ufixed80x54', 'ufixed80x55', 'ufixed80x56', 'ufixed80x57', 'ufixed80x58', 'ufixed80x59', 'ufixed80x60', 'ufixed80x61', 'ufixed80x62', 'ufixed80x63', 'ufixed80x64', 'ufixed80x65', 'ufixed80x66', 'ufixed80x67', 'ufixed80x68', 'ufixed80x69', 'ufixed80x70', 'ufixed80x71', 'ufixed80x72', 'ufixed80x73', 'ufixed80x74', 'ufixed80x75', 'ufixed80x76', 'ufixed80x77', 'ufixed80x78', 'ufixed80x79', 'ufixed80x80', 
    'ufixed88x1', 'ufixed88x2', 'ufixed88x3', 'ufixed88x4', 'ufixed88x5', 'ufixed88x6', 'ufixed88x7', 'ufixed88x8', 'ufixed88x9', 'ufixed88x10', 'ufixed88x11', 'ufixed88x12', 'ufixed88x13', 'ufixed88x14', 'ufixed88x15', 'ufixed88x16', 'ufixed88x17', 'ufixed88x18', 'ufixed88x19', 'ufixed88x20', 'ufixed88x21', 'ufixed88x22', 'ufixed88x23', 'ufixed88x24', 'ufixed88x25', 'ufixed88x26', 'ufixed88x27', 'ufixed88x28', 'ufixed88x29', 'ufixed88x30', 'ufixed88x31', 'ufixed88x32', 'ufixed88x33', 'ufixed88x34', 'ufixed88x35', 'ufixed88x36', 'ufixed88x37', 'ufixed88x38', 'ufixed88x39', 'ufixed88x40', 'ufixed88x41', 'ufixed88x42', 'ufixed88x43', 'ufixed88x44', 'ufixed88x45', 'ufixed88x46', 'ufixed88x47', 'ufixed88x48', 'ufixed88x49', 'ufixed88x50', 'ufixed88x51', 'ufixed88x52', 'ufixed88x53', 'ufixed88x54', 'ufixed88x55', 'ufixed88x56', 'ufixed88x57', 'ufixed88x58', 'ufixed88x59', 'ufixed88x60', 'ufixed88x61', 'ufixed88x62', 'ufixed88x63', 'ufixed88x64', 'ufixed88x65', 'ufixed88x66', 'ufixed88x67', 'ufixed88x68', 'ufixed88x69', 'ufixed88x70', 'ufixed88x71', 'ufixed88x72', 'ufixed88x73', 'ufixed88x74', 'ufixed88x75', 'ufixed88x76', 'ufixed88x77', 'ufixed88x78', 'ufixed88x79', 'ufixed88x80', 
    'ufixed96x1', 'ufixed96x2', 'ufixed96x3', 'ufixed96x4', 'ufixed96x5', 'ufixed96x6', 'ufixed96x7', 'ufixed96x8', 'ufixed96x9', 'ufixed96x10', 'ufixed96x11', 'ufixed96x12', 'ufixed96x13', 'ufixed96x14', 'ufixed96x15', 'ufixed96x16', 'ufixed96x17', 'ufixed96x18', 'ufixed96x19', 'ufixed96x20', 'ufixed96x21', 'ufixed96x22', 'ufixed96x23', 'ufixed96x24', 'ufixed96x25', 'ufixed96x26', 'ufixed96x27', 'ufixed96x28', 'ufixed96x29', 'ufixed96x30', 'ufixed96x31', 'ufixed96x32', 'ufixed96x33', 'ufixed96x34', 'ufixed96x35', 'ufixed96x36', 'ufixed96x37', 'ufixed96x38', 'ufixed96x39', 'ufixed96x40', 'ufixed96x41', 'ufixed96x42', 'ufixed96x43', 'ufixed96x44', 'ufixed96x45', 'ufixed96x46', 'ufixed96x47', 'ufixed96x48', 'ufixed96x49', 'ufixed96x50', 'ufixed96x51', 'ufixed96x52', 'ufixed96x53', 'ufixed96x54', 'ufixed96x55', 'ufixed96x56', 'ufixed96x57', 'ufixed96x58', 'ufixed96x59', 'ufixed96x60', 'ufixed96x61', 'ufixed96x62', 'ufixed96x63', 'ufixed96x64', 'ufixed96x65', 'ufixed96x66', 'ufixed96x67', 'ufixed96x68', 'ufixed96x69', 'ufixed96x70', 'ufixed96x71', 'ufixed96x72', 'ufixed96x73', 'ufixed96x74', 'ufixed96x75', 'ufixed96x76', 'ufixed96x77', 'ufixed96x78', 'ufixed96x79', 'ufixed96x80', 
    'ufixed104x1', 'ufixed104x2', 'ufixed104x3', 'ufixed104x4', 'ufixed104x5', 'ufixed104x6', 'ufixed104x7', 'ufixed104x8', 'ufixed104x9', 'ufixed104x10', 'ufixed104x11', 'ufixed104x12', 'ufixed104x13', 'ufixed104x14', 'ufixed104x15', 'ufixed104x16', 'ufixed104x17', 'ufixed104x18', 'ufixed104x19', 'ufixed104x20', 'ufixed104x21', 'ufixed104x22', 'ufixed104x23', 'ufixed104x24', 'ufixed104x25', 'ufixed104x26', 'ufixed104x27', 'ufixed104x28', 'ufixed104x29', 'ufixed104x30', 'ufixed104x31', 'ufixed104x32', 'ufixed104x33', 'ufixed104x34', 'ufixed104x35', 'ufixed104x36', 'ufixed104x37', 'ufixed104x38', 'ufixed104x39', 'ufixed104x40', 'ufixed104x41', 'ufixed104x42', 'ufixed104x43', 'ufixed104x44', 'ufixed104x45', 'ufixed104x46', 'ufixed104x47', 'ufixed104x48', 'ufixed104x49', 'ufixed104x50', 'ufixed104x51', 'ufixed104x52', 'ufixed104x53', 'ufixed104x54', 'ufixed104x55', 'ufixed104x56', 'ufixed104x57', 'ufixed104x58', 'ufixed104x59', 'ufixed104x60', 'ufixed104x61', 'ufixed104x62', 'ufixed104x63', 'ufixed104x64', 'ufixed104x65', 'ufixed104x66', 'ufixed104x67', 'ufixed104x68', 'ufixed104x69', 'ufixed104x70', 'ufixed104x71', 'ufixed104x72', 'ufixed104x73', 'ufixed104x74', 'ufixed104x75', 'ufixed104x76', 'ufixed104x77', 'ufixed104x78', 'ufixed104x79', 'ufixed104x80', 
    'ufixed112x1', 'ufixed112x2', 'ufixed112x3', 'ufixed112x4', 'ufixed112x5', 'ufixed112x6', 'ufixed112x7', 'ufixed112x8', 'ufixed112x9', 'ufixed112x10', 'ufixed112x11', 'ufixed112x12', 'ufixed112x13', 'ufixed112x14', 'ufixed112x15', 'ufixed112x16', 'ufixed112x17', 'ufixed112x18', 'ufixed112x19', 'ufixed112x20', 'ufixed112x21', 'ufixed112x22', 'ufixed112x23', 'ufixed112x24', 'ufixed112x25', 'ufixed112x26', 'ufixed112x27', 'ufixed112x28', 'ufixed112x29', 'ufixed112x30', 'ufixed112x31', 'ufixed112x32', 'ufixed112x33', 'ufixed112x34', 'ufixed112x35', 'ufixed112x36', 'ufixed112x37', 'ufixed112x38', 'ufixed112x39', 'ufixed112x40', 'ufixed112x41', 'ufixed112x42', 'ufixed112x43', 'ufixed112x44', 'ufixed112x45', 'ufixed112x46', 'ufixed112x47', 'ufixed112x48', 'ufixed112x49', 'ufixed112x50', 'ufixed112x51', 'ufixed112x52', 'ufixed112x53', 'ufixed112x54', 'ufixed112x55', 'ufixed112x56', 'ufixed112x57', 'ufixed112x58', 'ufixed112x59', 'ufixed112x60', 'ufixed112x61', 'ufixed112x62', 'ufixed112x63', 'ufixed112x64', 'ufixed112x65', 'ufixed112x66', 'ufixed112x67', 'ufixed112x68', 'ufixed112x69', 'ufixed112x70', 'ufixed112x71', 'ufixed112x72', 'ufixed112x73', 'ufixed112x74', 'ufixed112x75', 'ufixed112x76', 'ufixed112x77', 'ufixed112x78', 'ufixed112x79', 'ufixed112x80', 
    'ufixed120x1', 'ufixed120x2', 'ufixed120x3', 'ufixed120x4', 'ufixed120x5', 'ufixed120x6', 'ufixed120x7', 'ufixed120x8', 'ufixed120x9', 'ufixed120x10', 'ufixed120x11', 'ufixed120x12', 'ufixed120x13', 'ufixed120x14', 'ufixed120x15', 'ufixed120x16', 'ufixed120x17', 'ufixed120x18', 'ufixed120x19', 'ufixed120x20', 'ufixed120x21', 'ufixed120x22', 'ufixed120x23', 'ufixed120x24', 'ufixed120x25', 'ufixed120x26', 'ufixed120x27', 'ufixed120x28', 'ufixed120x29', 'ufixed120x30', 'ufixed120x31', 'ufixed120x32', 'ufixed120x33', 'ufixed120x34', 'ufixed120x35', 'ufixed120x36', 'ufixed120x37', 'ufixed120x38', 'ufixed120x39', 'ufixed120x40', 'ufixed120x41', 'ufixed120x42', 'ufixed120x43', 'ufixed120x44', 'ufixed120x45', 'ufixed120x46', 'ufixed120x47', 'ufixed120x48', 'ufixed120x49', 'ufixed120x50', 'ufixed120x51', 'ufixed120x52', 'ufixed120x53', 'ufixed120x54', 'ufixed120x55', 'ufixed120x56', 'ufixed120x57', 'ufixed120x58', 'ufixed120x59', 'ufixed120x60', 'ufixed120x61', 'ufixed120x62', 'ufixed120x63', 'ufixed120x64', 'ufixed120x65', 'ufixed120x66', 'ufixed120x67', 'ufixed120x68', 'ufixed120x69', 'ufixed120x70', 'ufixed120x71', 'ufixed120x72', 'ufixed120x73', 'ufixed120x74', 'ufixed120x75', 'ufixed120x76', 'ufixed120x77', 'ufixed120x78', 'ufixed120x79', 'ufixed120x80', 
    'ufixed128x1', 'ufixed128x2', 'ufixed128x3', 'ufixed128x4', 'ufixed128x5', 'ufixed128x6', 'ufixed128x7', 'ufixed128x8', 'ufixed128x9', 'ufixed128x10', 'ufixed128x11', 'ufixed128x12', 'ufixed128x13', 'ufixed128x14', 'ufixed128x15', 'ufixed128x16', 'ufixed128x17', 'ufixed128x18', 'ufixed128x19', 'ufixed128x20', 'ufixed128x21', 'ufixed128x22', 'ufixed128x23', 'ufixed128x24', 'ufixed128x25', 'ufixed128x26', 'ufixed128x27', 'ufixed128x28', 'ufixed128x29', 'ufixed128x30', 'ufixed128x31', 'ufixed128x32', 'ufixed128x33', 'ufixed128x34', 'ufixed128x35', 'ufixed128x36', 'ufixed128x37', 'ufixed128x38', 'ufixed128x39', 'ufixed128x40', 'ufixed128x41', 'ufixed128x42', 'ufixed128x43', 'ufixed128x44', 'ufixed128x45', 'ufixed128x46', 'ufixed128x47', 'ufixed128x48', 'ufixed128x49', 'ufixed128x50', 'ufixed128x51', 'ufixed128x52', 'ufixed128x53', 'ufixed128x54', 'ufixed128x55', 'ufixed128x56', 'ufixed128x57', 'ufixed128x58', 'ufixed128x59', 'ufixed128x60', 'ufixed128x61', 'ufixed128x62', 'ufixed128x63', 'ufixed128x64', 'ufixed128x65', 'ufixed128x66', 'ufixed128x67', 'ufixed128x68', 'ufixed128x69', 'ufixed128x70', 'ufixed128x71', 'ufixed128x72', 'ufixed128x73', 'ufixed128x74', 'ufixed128x75', 'ufixed128x76', 'ufixed128x77', 'ufixed128x78', 'ufixed128x79', 'ufixed128x80', 
    'ufixed136x1', 'ufixed136x2', 'ufixed136x3', 'ufixed136x4', 'ufixed136x5', 'ufixed136x6', 'ufixed136x7', 'ufixed136x8', 'ufixed136x9', 'ufixed136x10', 'ufixed136x11', 'ufixed136x12', 'ufixed136x13', 'ufixed136x14', 'ufixed136x15', 'ufixed136x16', 'ufixed136x17', 'ufixed136x18', 'ufixed136x19', 'ufixed136x20', 'ufixed136x21', 'ufixed136x22', 'ufixed136x23', 'ufixed136x24', 'ufixed136x25', 'ufixed136x26', 'ufixed136x27', 'ufixed136x28', 'ufixed136x29', 'ufixed136x30', 'ufixed136x31', 'ufixed136x32', 'ufixed136x33', 'ufixed136x34', 'ufixed136x35', 'ufixed136x36', 'ufixed136x37', 'ufixed136x38', 'ufixed136x39', 'ufixed136x40', 'ufixed136x41', 'ufixed136x42', 'ufixed136x43', 'ufixed136x44', 'ufixed136x45', 'ufixed136x46', 'ufixed136x47', 'ufixed136x48', 'ufixed136x49', 'ufixed136x50', 'ufixed136x51', 'ufixed136x52', 'ufixed136x53', 'ufixed136x54', 'ufixed136x55', 'ufixed136x56', 'ufixed136x57', 'ufixed136x58', 'ufixed136x59', 'ufixed136x60', 'ufixed136x61', 'ufixed136x62', 'ufixed136x63', 'ufixed136x64', 'ufixed136x65', 'ufixed136x66', 'ufixed136x67', 'ufixed136x68', 'ufixed136x69', 'ufixed136x70', 'ufixed136x71', 'ufixed136x72', 'ufixed136x73', 'ufixed136x74', 'ufixed136x75', 'ufixed136x76', 'ufixed136x77', 'ufixed136x78', 'ufixed136x79', 'ufixed136x80', 
    'ufixed144x1', 'ufixed144x2', 'ufixed144x3', 'ufixed144x4', 'ufixed144x5', 'ufixed144x6', 'ufixed144x7', 'ufixed144x8', 'ufixed144x9', 'ufixed144x10', 'ufixed144x11', 'ufixed144x12', 'ufixed144x13', 'ufixed144x14', 'ufixed144x15', 'ufixed144x16', 'ufixed144x17', 'ufixed144x18', 'ufixed144x19', 'ufixed144x20', 'ufixed144x21', 'ufixed144x22', 'ufixed144x23', 'ufixed144x24', 'ufixed144x25', 'ufixed144x26', 'ufixed144x27', 'ufixed144x28', 'ufixed144x29', 'ufixed144x30', 'ufixed144x31', 'ufixed144x32', 'ufixed144x33', 'ufixed144x34', 'ufixed144x35', 'ufixed144x36', 'ufixed144x37', 'ufixed144x38', 'ufixed144x39', 'ufixed144x40', 'ufixed144x41', 'ufixed144x42', 'ufixed144x43', 'ufixed144x44', 'ufixed144x45', 'ufixed144x46', 'ufixed144x47', 'ufixed144x48', 'ufixed144x49', 'ufixed144x50', 'ufixed144x51', 'ufixed144x52', 'ufixed144x53', 'ufixed144x54', 'ufixed144x55', 'ufixed144x56', 'ufixed144x57', 'ufixed144x58', 'ufixed144x59', 'ufixed144x60', 'ufixed144x61', 'ufixed144x62', 'ufixed144x63', 'ufixed144x64', 'ufixed144x65', 'ufixed144x66', 'ufixed144x67', 'ufixed144x68', 'ufixed144x69', 'ufixed144x70', 'ufixed144x71', 'ufixed144x72', 'ufixed144x73', 'ufixed144x74', 'ufixed144x75', 'ufixed144x76', 'ufixed144x77', 'ufixed144x78', 'ufixed144x79', 'ufixed144x80', 
    'ufixed152x1', 'ufixed152x2', 'ufixed152x3', 'ufixed152x4', 'ufixed152x5', 'ufixed152x6', 'ufixed152x7', 'ufixed152x8', 'ufixed152x9', 'ufixed152x10', 'ufixed152x11', 'ufixed152x12', 'ufixed152x13', 'ufixed152x14', 'ufixed152x15', 'ufixed152x16', 'ufixed152x17', 'ufixed152x18', 'ufixed152x19', 'ufixed152x20', 'ufixed152x21', 'ufixed152x22', 'ufixed152x23', 'ufixed152x24', 'ufixed152x25', 'ufixed152x26', 'ufixed152x27', 'ufixed152x28', 'ufixed152x29', 'ufixed152x30', 'ufixed152x31', 'ufixed152x32', 'ufixed152x33', 'ufixed152x34', 'ufixed152x35', 'ufixed152x36', 'ufixed152x37', 'ufixed152x38', 'ufixed152x39', 'ufixed152x40', 'ufixed152x41', 'ufixed152x42', 'ufixed152x43', 'ufixed152x44', 'ufixed152x45', 'ufixed152x46', 'ufixed152x47', 'ufixed152x48', 'ufixed152x49', 'ufixed152x50', 'ufixed152x51', 'ufixed152x52', 'ufixed152x53', 'ufixed152x54', 'ufixed152x55', 'ufixed152x56', 'ufixed152x57', 'ufixed152x58', 'ufixed152x59', 'ufixed152x60', 'ufixed152x61', 'ufixed152x62', 'ufixed152x63', 'ufixed152x64', 'ufixed152x65', 'ufixed152x66', 'ufixed152x67', 'ufixed152x68', 'ufixed152x69', 'ufixed152x70', 'ufixed152x71', 'ufixed152x72', 'ufixed152x73', 'ufixed152x74', 'ufixed152x75', 'ufixed152x76', 'ufixed152x77', 'ufixed152x78', 'ufixed152x79', 'ufixed152x80', 
    'ufixed160x1', 'ufixed160x2', 'ufixed160x3', 'ufixed160x4', 'ufixed160x5', 'ufixed160x6', 'ufixed160x7', 'ufixed160x8', 'ufixed160x9', 'ufixed160x10', 'ufixed160x11', 'ufixed160x12', 'ufixed160x13', 'ufixed160x14', 'ufixed160x15', 'ufixed160x16', 'ufixed160x17', 'ufixed160x18', 'ufixed160x19', 'ufixed160x20', 'ufixed160x21', 'ufixed160x22', 'ufixed160x23', 'ufixed160x24', 'ufixed160x25', 'ufixed160x26', 'ufixed160x27', 'ufixed160x28', 'ufixed160x29', 'ufixed160x30', 'ufixed160x31', 'ufixed160x32', 'ufixed160x33', 'ufixed160x34', 'ufixed160x35', 'ufixed160x36', 'ufixed160x37', 'ufixed160x38', 'ufixed160x39', 'ufixed160x40', 'ufixed160x41', 'ufixed160x42', 'ufixed160x43', 'ufixed160x44', 'ufixed160x45', 'ufixed160x46', 'ufixed160x47', 'ufixed160x48', 'ufixed160x49', 'ufixed160x50', 'ufixed160x51', 'ufixed160x52', 'ufixed160x53', 'ufixed160x54', 'ufixed160x55', 'ufixed160x56', 'ufixed160x57', 'ufixed160x58', 'ufixed160x59', 'ufixed160x60', 'ufixed160x61', 'ufixed160x62', 'ufixed160x63', 'ufixed160x64', 'ufixed160x65', 'ufixed160x66', 'ufixed160x67', 'ufixed160x68', 'ufixed160x69', 'ufixed160x70', 'ufixed160x71', 'ufixed160x72', 'ufixed160x73', 'ufixed160x74', 'ufixed160x75', 'ufixed160x76', 'ufixed160x77', 'ufixed160x78', 'ufixed160x79', 'ufixed160x80', 
    'ufixed168x1', 'ufixed168x2', 'ufixed168x3', 'ufixed168x4', 'ufixed168x5', 'ufixed168x6', 'ufixed168x7', 'ufixed168x8', 'ufixed168x9', 'ufixed168x10', 'ufixed168x11', 'ufixed168x12', 'ufixed168x13', 'ufixed168x14', 'ufixed168x15', 'ufixed168x16', 'ufixed168x17', 'ufixed168x18', 'ufixed168x19', 'ufixed168x20', 'ufixed168x21', 'ufixed168x22', 'ufixed168x23', 'ufixed168x24', 'ufixed168x25', 'ufixed168x26', 'ufixed168x27', 'ufixed168x28', 'ufixed168x29', 'ufixed168x30', 'ufixed168x31', 'ufixed168x32', 'ufixed168x33', 'ufixed168x34', 'ufixed168x35', 'ufixed168x36', 'ufixed168x37', 'ufixed168x38', 'ufixed168x39', 'ufixed168x40', 'ufixed168x41', 'ufixed168x42', 'ufixed168x43', 'ufixed168x44', 'ufixed168x45', 'ufixed168x46', 'ufixed168x47', 'ufixed168x48', 'ufixed168x49', 'ufixed168x50', 'ufixed168x51', 'ufixed168x52', 'ufixed168x53', 'ufixed168x54', 'ufixed168x55', 'ufixed168x56', 'ufixed168x57', 'ufixed168x58', 'ufixed168x59', 'ufixed168x60', 'ufixed168x61', 'ufixed168x62', 'ufixed168x63', 'ufixed168x64', 'ufixed168x65', 'ufixed168x66', 'ufixed168x67', 'ufixed168x68', 'ufixed168x69', 'ufixed168x70', 'ufixed168x71', 'ufixed168x72', 'ufixed168x73', 'ufixed168x74', 'ufixed168x75', 'ufixed168x76', 'ufixed168x77', 'ufixed168x78', 'ufixed168x79', 'ufixed168x80', 
    'ufixed176x1', 'ufixed176x2', 'ufixed176x3', 'ufixed176x4', 'ufixed176x5', 'ufixed176x6', 'ufixed176x7', 'ufixed176x8', 'ufixed176x9', 'ufixed176x10', 'ufixed176x11', 'ufixed176x12', 'ufixed176x13', 'ufixed176x14', 'ufixed176x15', 'ufixed176x16', 'ufixed176x17', 'ufixed176x18', 'ufixed176x19', 'ufixed176x20', 'ufixed176x21', 'ufixed176x22', 'ufixed176x23', 'ufixed176x24', 'ufixed176x25', 'ufixed176x26', 'ufixed176x27', 'ufixed176x28', 'ufixed176x29', 'ufixed176x30', 'ufixed176x31', 'ufixed176x32', 'ufixed176x33', 'ufixed176x34', 'ufixed176x35', 'ufixed176x36', 'ufixed176x37', 'ufixed176x38', 'ufixed176x39', 'ufixed176x40', 'ufixed176x41', 'ufixed176x42', 'ufixed176x43', 'ufixed176x44', 'ufixed176x45', 'ufixed176x46', 'ufixed176x47', 'ufixed176x48', 'ufixed176x49', 'ufixed176x50', 'ufixed176x51', 'ufixed176x52', 'ufixed176x53', 'ufixed176x54', 'ufixed176x55', 'ufixed176x56', 'ufixed176x57', 'ufixed176x58', 'ufixed176x59', 'ufixed176x60', 'ufixed176x61', 'ufixed176x62', 'ufixed176x63', 'ufixed176x64', 'ufixed176x65', 'ufixed176x66', 'ufixed176x67', 'ufixed176x68', 'ufixed176x69', 'ufixed176x70', 'ufixed176x71', 'ufixed176x72', 'ufixed176x73', 'ufixed176x74', 'ufixed176x75', 'ufixed176x76', 'ufixed176x77', 'ufixed176x78', 'ufixed176x79', 'ufixed176x80', 
    'ufixed184x1', 'ufixed184x2', 'ufixed184x3', 'ufixed184x4', 'ufixed184x5', 'ufixed184x6', 'ufixed184x7', 'ufixed184x8', 'ufixed184x9', 'ufixed184x10', 'ufixed184x11', 'ufixed184x12', 'ufixed184x13', 'ufixed184x14', 'ufixed184x15', 'ufixed184x16', 'ufixed184x17', 'ufixed184x18', 'ufixed184x19', 'ufixed184x20', 'ufixed184x21', 'ufixed184x22', 'ufixed184x23', 'ufixed184x24', 'ufixed184x25', 'ufixed184x26', 'ufixed184x27', 'ufixed184x28', 'ufixed184x29', 'ufixed184x30', 'ufixed184x31', 'ufixed184x32', 'ufixed184x33', 'ufixed184x34', 'ufixed184x35', 'ufixed184x36', 'ufixed184x37', 'ufixed184x38', 'ufixed184x39', 'ufixed184x40', 'ufixed184x41', 'ufixed184x42', 'ufixed184x43', 'ufixed184x44', 'ufixed184x45', 'ufixed184x46', 'ufixed184x47', 'ufixed184x48', 'ufixed184x49', 'ufixed184x50', 'ufixed184x51', 'ufixed184x52', 'ufixed184x53', 'ufixed184x54', 'ufixed184x55', 'ufixed184x56', 'ufixed184x57', 'ufixed184x58', 'ufixed184x59', 'ufixed184x60', 'ufixed184x61', 'ufixed184x62', 'ufixed184x63', 'ufixed184x64', 'ufixed184x65', 'ufixed184x66', 'ufixed184x67', 'ufixed184x68', 'ufixed184x69', 'ufixed184x70', 'ufixed184x71', 'ufixed184x72', 'ufixed184x73', 'ufixed184x74', 'ufixed184x75', 'ufixed184x76', 'ufixed184x77', 'ufixed184x78', 'ufixed184x79', 'ufixed184x80', 
    'ufixed192x1', 'ufixed192x2', 'ufixed192x3', 'ufixed192x4', 'ufixed192x5', 'ufixed192x6', 'ufixed192x7', 'ufixed192x8', 'ufixed192x9', 'ufixed192x10', 'ufixed192x11', 'ufixed192x12', 'ufixed192x13', 'ufixed192x14', 'ufixed192x15', 'ufixed192x16', 'ufixed192x17', 'ufixed192x18', 'ufixed192x19', 'ufixed192x20', 'ufixed192x21', 'ufixed192x22', 'ufixed192x23', 'ufixed192x24', 'ufixed192x25', 'ufixed192x26', 'ufixed192x27', 'ufixed192x28', 'ufixed192x29', 'ufixed192x30', 'ufixed192x31', 'ufixed192x32', 'ufixed192x33', 'ufixed192x34', 'ufixed192x35', 'ufixed192x36', 'ufixed192x37', 'ufixed192x38', 'ufixed192x39', 'ufixed192x40', 'ufixed192x41', 'ufixed192x42', 'ufixed192x43', 'ufixed192x44', 'ufixed192x45', 'ufixed192x46', 'ufixed192x47', 'ufixed192x48', 'ufixed192x49', 'ufixed192x50', 'ufixed192x51', 'ufixed192x52', 'ufixed192x53', 'ufixed192x54', 'ufixed192x55', 'ufixed192x56', 'ufixed192x57', 'ufixed192x58', 'ufixed192x59', 'ufixed192x60', 'ufixed192x61', 'ufixed192x62', 'ufixed192x63', 'ufixed192x64', 'ufixed192x65', 'ufixed192x66', 'ufixed192x67', 'ufixed192x68', 'ufixed192x69', 'ufixed192x70', 'ufixed192x71', 'ufixed192x72', 'ufixed192x73', 'ufixed192x74', 'ufixed192x75', 'ufixed192x76', 'ufixed192x77', 'ufixed192x78', 'ufixed192x79', 'ufixed192x80', 
    'ufixed200x1', 'ufixed200x2', 'ufixed200x3', 'ufixed200x4', 'ufixed200x5', 'ufixed200x6', 'ufixed200x7', 'ufixed200x8', 'ufixed200x9', 'ufixed200x10', 'ufixed200x11', 'ufixed200x12', 'ufixed200x13', 'ufixed200x14', 'ufixed200x15', 'ufixed200x16', 'ufixed200x17', 'ufixed200x18', 'ufixed200x19', 'ufixed200x20', 'ufixed200x21', 'ufixed200x22', 'ufixed200x23', 'ufixed200x24', 'ufixed200x25', 'ufixed200x26', 'ufixed200x27', 'ufixed200x28', 'ufixed200x29', 'ufixed200x30', 'ufixed200x31', 'ufixed200x32', 'ufixed200x33', 'ufixed200x34', 'ufixed200x35', 'ufixed200x36', 'ufixed200x37', 'ufixed200x38', 'ufixed200x39', 'ufixed200x40', 'ufixed200x41', 'ufixed200x42', 'ufixed200x43', 'ufixed200x44', 'ufixed200x45', 'ufixed200x46', 'ufixed200x47', 'ufixed200x48', 'ufixed200x49', 'ufixed200x50', 'ufixed200x51', 'ufixed200x52', 'ufixed200x53', 'ufixed200x54', 'ufixed200x55', 'ufixed200x56', 'ufixed200x57', 'ufixed200x58', 'ufixed200x59', 'ufixed200x60', 'ufixed200x61', 'ufixed200x62', 'ufixed200x63', 'ufixed200x64', 'ufixed200x65', 'ufixed200x66', 'ufixed200x67', 'ufixed200x68', 'ufixed200x69', 'ufixed200x70', 'ufixed200x71', 'ufixed200x72', 'ufixed200x73', 'ufixed200x74', 'ufixed200x75', 'ufixed200x76', 'ufixed200x77', 'ufixed200x78', 'ufixed200x79', 'ufixed200x80', 
    'ufixed208x1', 'ufixed208x2', 'ufixed208x3', 'ufixed208x4', 'ufixed208x5', 'ufixed208x6', 'ufixed208x7', 'ufixed208x8', 'ufixed208x9', 'ufixed208x10', 'ufixed208x11', 'ufixed208x12', 'ufixed208x13', 'ufixed208x14', 'ufixed208x15', 'ufixed208x16', 'ufixed208x17', 'ufixed208x18', 'ufixed208x19', 'ufixed208x20', 'ufixed208x21', 'ufixed208x22', 'ufixed208x23', 'ufixed208x24', 'ufixed208x25', 'ufixed208x26', 'ufixed208x27', 'ufixed208x28', 'ufixed208x29', 'ufixed208x30', 'ufixed208x31', 'ufixed208x32', 'ufixed208x33', 'ufixed208x34', 'ufixed208x35', 'ufixed208x36', 'ufixed208x37', 'ufixed208x38', 'ufixed208x39', 'ufixed208x40', 'ufixed208x41', 'ufixed208x42', 'ufixed208x43', 'ufixed208x44', 'ufixed208x45', 'ufixed208x46', 'ufixed208x47', 'ufixed208x48', 'ufixed208x49', 'ufixed208x50', 'ufixed208x51', 'ufixed208x52', 'ufixed208x53', 'ufixed208x54', 'ufixed208x55', 'ufixed208x56', 'ufixed208x57', 'ufixed208x58', 'ufixed208x59', 'ufixed208x60', 'ufixed208x61', 'ufixed208x62', 'ufixed208x63', 'ufixed208x64', 'ufixed208x65', 'ufixed208x66', 'ufixed208x67', 'ufixed208x68', 'ufixed208x69', 'ufixed208x70', 'ufixed208x71', 'ufixed208x72', 'ufixed208x73', 'ufixed208x74', 'ufixed208x75', 'ufixed208x76', 'ufixed208x77', 'ufixed208x78', 'ufixed208x79', 'ufixed208x80', 
    'ufixed216x1', 'ufixed216x2', 'ufixed216x3', 'ufixed216x4', 'ufixed216x5', 'ufixed216x6', 'ufixed216x7', 'ufixed216x8', 'ufixed216x9', 'ufixed216x10', 'ufixed216x11', 'ufixed216x12', 'ufixed216x13', 'ufixed216x14', 'ufixed216x15', 'ufixed216x16', 'ufixed216x17', 'ufixed216x18', 'ufixed216x19', 'ufixed216x20', 'ufixed216x21', 'ufixed216x22', 'ufixed216x23', 'ufixed216x24', 'ufixed216x25', 'ufixed216x26', 'ufixed216x27', 'ufixed216x28', 'ufixed216x29', 'ufixed216x30', 'ufixed216x31', 'ufixed216x32', 'ufixed216x33', 'ufixed216x34', 'ufixed216x35', 'ufixed216x36', 'ufixed216x37', 'ufixed216x38', 'ufixed216x39', 'ufixed216x40', 'ufixed216x41', 'ufixed216x42', 'ufixed216x43', 'ufixed216x44', 'ufixed216x45', 'ufixed216x46', 'ufixed216x47', 'ufixed216x48', 'ufixed216x49', 'ufixed216x50', 'ufixed216x51', 'ufixed216x52', 'ufixed216x53', 'ufixed216x54', 'ufixed216x55', 'ufixed216x56', 'ufixed216x57', 'ufixed216x58', 'ufixed216x59', 'ufixed216x60', 'ufixed216x61', 'ufixed216x62', 'ufixed216x63', 'ufixed216x64', 'ufixed216x65', 'ufixed216x66', 'ufixed216x67', 'ufixed216x68', 'ufixed216x69', 'ufixed216x70', 'ufixed216x71', 'ufixed216x72', 'ufixed216x73', 'ufixed216x74', 'ufixed216x75', 'ufixed216x76', 'ufixed216x77', 'ufixed216x78', 'ufixed216x79', 'ufixed216x80', 
    'ufixed224x1', 'ufixed224x2', 'ufixed224x3', 'ufixed224x4', 'ufixed224x5', 'ufixed224x6', 'ufixed224x7', 'ufixed224x8', 'ufixed224x9', 'ufixed224x10', 'ufixed224x11', 'ufixed224x12', 'ufixed224x13', 'ufixed224x14', 'ufixed224x15', 'ufixed224x16', 'ufixed224x17', 'ufixed224x18', 'ufixed224x19', 'ufixed224x20', 'ufixed224x21', 'ufixed224x22', 'ufixed224x23', 'ufixed224x24', 'ufixed224x25', 'ufixed224x26', 'ufixed224x27', 'ufixed224x28', 'ufixed224x29', 'ufixed224x30', 'ufixed224x31', 'ufixed224x32', 'ufixed224x33', 'ufixed224x34', 'ufixed224x35', 'ufixed224x36', 'ufixed224x37', 'ufixed224x38', 'ufixed224x39', 'ufixed224x40', 'ufixed224x41', 'ufixed224x42', 'ufixed224x43', 'ufixed224x44', 'ufixed224x45', 'ufixed224x46', 'ufixed224x47', 'ufixed224x48', 'ufixed224x49', 'ufixed224x50', 'ufixed224x51', 'ufixed224x52', 'ufixed224x53', 'ufixed224x54', 'ufixed224x55', 'ufixed224x56', 'ufixed224x57', 'ufixed224x58', 'ufixed224x59', 'ufixed224x60', 'ufixed224x61', 'ufixed224x62', 'ufixed224x63', 'ufixed224x64', 'ufixed224x65', 'ufixed224x66', 'ufixed224x67', 'ufixed224x68', 'ufixed224x69', 'ufixed224x70', 'ufixed224x71', 'ufixed224x72', 'ufixed224x73', 'ufixed224x74', 'ufixed224x75', 'ufixed224x76', 'ufixed224x77', 'ufixed224x78', 'ufixed224x79', 'ufixed224x80', 
    'ufixed232x1', 'ufixed232x2', 'ufixed232x3', 'ufixed232x4', 'ufixed232x5', 'ufixed232x6', 'ufixed232x7', 'ufixed232x8', 'ufixed232x9', 'ufixed232x10', 'ufixed232x11', 'ufixed232x12', 'ufixed232x13', 'ufixed232x14', 'ufixed232x15', 'ufixed232x16', 'ufixed232x17', 'ufixed232x18', 'ufixed232x19', 'ufixed232x20', 'ufixed232x21', 'ufixed232x22', 'ufixed232x23', 'ufixed232x24', 'ufixed232x25', 'ufixed232x26', 'ufixed232x27', 'ufixed232x28', 'ufixed232x29', 'ufixed232x30', 'ufixed232x31', 'ufixed232x32', 'ufixed232x33', 'ufixed232x34', 'ufixed232x35', 'ufixed232x36', 'ufixed232x37', 'ufixed232x38', 'ufixed232x39', 'ufixed232x40', 'ufixed232x41', 'ufixed232x42', 'ufixed232x43', 'ufixed232x44', 'ufixed232x45', 'ufixed232x46', 'ufixed232x47', 'ufixed232x48', 'ufixed232x49', 'ufixed232x50', 'ufixed232x51', 'ufixed232x52', 'ufixed232x53', 'ufixed232x54', 'ufixed232x55', 'ufixed232x56', 'ufixed232x57', 'ufixed232x58', 'ufixed232x59', 'ufixed232x60', 'ufixed232x61', 'ufixed232x62', 'ufixed232x63', 'ufixed232x64', 'ufixed232x65', 'ufixed232x66', 'ufixed232x67', 'ufixed232x68', 'ufixed232x69', 'ufixed232x70', 'ufixed232x71', 'ufixed232x72', 'ufixed232x73', 'ufixed232x74', 'ufixed232x75', 'ufixed232x76', 'ufixed232x77', 'ufixed232x78', 'ufixed232x79', 'ufixed232x80', 
    'ufixed240x1', 'ufixed240x2', 'ufixed240x3', 'ufixed240x4', 'ufixed240x5', 'ufixed240x6', 'ufixed240x7', 'ufixed240x8', 'ufixed240x9', 'ufixed240x10', 'ufixed240x11', 'ufixed240x12', 'ufixed240x13', 'ufixed240x14', 'ufixed240x15', 'ufixed240x16', 'ufixed240x17', 'ufixed240x18', 'ufixed240x19', 'ufixed240x20', 'ufixed240x21', 'ufixed240x22', 'ufixed240x23', 'ufixed240x24', 'ufixed240x25', 'ufixed240x26', 'ufixed240x27', 'ufixed240x28', 'ufixed240x29', 'ufixed240x30', 'ufixed240x31', 'ufixed240x32', 'ufixed240x33', 'ufixed240x34', 'ufixed240x35', 'ufixed240x36', 'ufixed240x37', 'ufixed240x38', 'ufixed240x39', 'ufixed240x40', 'ufixed240x41', 'ufixed240x42', 'ufixed240x43', 'ufixed240x44', 'ufixed240x45', 'ufixed240x46', 'ufixed240x47', 'ufixed240x48', 'ufixed240x49', 'ufixed240x50', 'ufixed240x51', 'ufixed240x52', 'ufixed240x53', 'ufixed240x54', 'ufixed240x55', 'ufixed240x56', 'ufixed240x57', 'ufixed240x58', 'ufixed240x59', 'ufixed240x60', 'ufixed240x61', 'ufixed240x62', 'ufixed240x63', 'ufixed240x64', 'ufixed240x65', 'ufixed240x66', 'ufixed240x67', 'ufixed240x68', 'ufixed240x69', 'ufixed240x70', 'ufixed240x71', 'ufixed240x72', 'ufixed240x73', 'ufixed240x74', 'ufixed240x75', 'ufixed240x76', 'ufixed240x77', 'ufixed240x78', 'ufixed240x79', 'ufixed240x80', 
    'ufixed248x1', 'ufixed248x2', 'ufixed248x3', 'ufixed248x4', 'ufixed248x5', 'ufixed248x6', 'ufixed248x7', 'ufixed248x8', 'ufixed248x9', 'ufixed248x10', 'ufixed248x11', 'ufixed248x12', 'ufixed248x13', 'ufixed248x14', 'ufixed248x15', 'ufixed248x16', 'ufixed248x17', 'ufixed248x18', 'ufixed248x19', 'ufixed248x20', 'ufixed248x21', 'ufixed248x22', 'ufixed248x23', 'ufixed248x24', 'ufixed248x25', 'ufixed248x26', 'ufixed248x27', 'ufixed248x28', 'ufixed248x29', 'ufixed248x30', 'ufixed248x31', 'ufixed248x32', 'ufixed248x33', 'ufixed248x34', 'ufixed248x35', 'ufixed248x36', 'ufixed248x37', 'ufixed248x38', 'ufixed248x39', 'ufixed248x40', 'ufixed248x41', 'ufixed248x42', 'ufixed248x43', 'ufixed248x44', 'ufixed248x45', 'ufixed248x46', 'ufixed248x47', 'ufixed248x48', 'ufixed248x49', 'ufixed248x50', 'ufixed248x51', 'ufixed248x52', 'ufixed248x53', 'ufixed248x54', 'ufixed248x55', 'ufixed248x56', 'ufixed248x57', 'ufixed248x58', 'ufixed248x59', 'ufixed248x60', 'ufixed248x61', 'ufixed248x62', 'ufixed248x63', 'ufixed248x64', 'ufixed248x65', 'ufixed248x66', 'ufixed248x67', 'ufixed248x68', 'ufixed248x69', 'ufixed248x70', 'ufixed248x71', 'ufixed248x72', 'ufixed248x73', 'ufixed248x74', 'ufixed248x75', 'ufixed248x76', 'ufixed248x77', 'ufixed248x78', 'ufixed248x79', 'ufixed248x80', 
    'ufixed256x1', 'ufixed256x2', 'ufixed256x3', 'ufixed256x4', 'ufixed256x5', 'ufixed256x6', 'ufixed256x7', 'ufixed256x8', 'ufixed256x9', 'ufixed256x10', 'ufixed256x11', 'ufixed256x12', 'ufixed256x13', 'ufixed256x14', 'ufixed256x15', 'ufixed256x16', 'ufixed256x17', 'ufixed256x18', 'ufixed256x19', 'ufixed256x20', 'ufixed256x21', 'ufixed256x22', 'ufixed256x23', 'ufixed256x24', 'ufixed256x25', 'ufixed256x26', 'ufixed256x27', 'ufixed256x28', 'ufixed256x29', 'ufixed256x30', 'ufixed256x31', 'ufixed256x32', 'ufixed256x33', 'ufixed256x34', 'ufixed256x35', 'ufixed256x36', 'ufixed256x37', 'ufixed256x38', 'ufixed256x39', 'ufixed256x40', 'ufixed256x41', 'ufixed256x42', 'ufixed256x43', 'ufixed256x44', 'ufixed256x45', 'ufixed256x46', 'ufixed256x47', 'ufixed256x48', 'ufixed256x49', 'ufixed256x50', 'ufixed256x51', 'ufixed256x52', 'ufixed256x53', 'ufixed256x54', 'ufixed256x55', 'ufixed256x56', 'ufixed256x57', 'ufixed256x58', 'ufixed256x59', 'ufixed256x60', 'ufixed256x61', 'ufixed256x62', 'ufixed256x63', 'ufixed256x64', 'ufixed256x65', 'ufixed256x66', 'ufixed256x67', 'ufixed256x68', 'ufixed256x69', 'ufixed256x70', 'ufixed256x71', 'ufixed256x72', 'ufixed256x73', 'ufixed256x74', 'ufixed256x75', 'ufixed256x76', 'ufixed256x77', 'ufixed256x78', 'ufixed256x79', 'ufixed256x80', 

    'fixed', 'ufixed',

    'bytes1', 'bytes2', 'bytes3', 'bytes4', 'bytes5', 'bytes6', 'bytes7', 'bytes8', 
    'bytes9', 'bytes10', 'bytes11', 'bytes12', 'bytes13', 'bytes14', 'bytes15', 'bytes16', 
    'bytes17', 'bytes18', 'bytes19', 'bytes20', 'bytes21', 'bytes22', 'bytes23', 'bytes24', 
    'bytes25', 'bytes26', 'bytes27', 'bytes28', 'bytes29', 'bytes30', 'bytes31', 'bytes32', 

    'function',

    'bytes',

    'string'
)

EVM_OPCODE = {
    '00': 'STOP',
    '01': 'ADD',
    '02': 'MUL',
    '03': 'SUB',
    '04': 'DIV',
    '05': 'SDIV',
    '06': 'MOD',
    '07': 'SMOD',
    '08': 'ADDMOD',
    '09': 'MULMOD',
    '0a': 'EXP',
    '0b': 'SIGNEXTEND',
    '0c': '',
    '0d': '',
    '0e': '',
    '0f': '',

    '10': 'LT',
    '11': 'GT',
    '12': 'SLT',
    '13': 'SGT',
    '14': 'EQ',
    '15': 'ISZERO',
    '16': 'AND',
    '17': 'OR',
    '18': 'XOR',
    '19': 'NOT',
    '1a': 'BYTE',
    '1b': 'SHL',
    '1c': 'SHR',
    '1d': 'SAR',
    '1e': '',
    '1f': '',

    '20': 'SHA3',
    '21': '',
    '22': '',
    '23': '',
    '24': '',
    '25': '',
    '26': '',
    '27': '',
    '28': '',
    '29': '',
    '2a': '',
    '2b': '',
    '2c': '',
    '2d': '',
    '2e': '',
    '2f': '',

    '30': 'ADDRESS',
    '31': 'BALANCE',
    '32': 'ORIGIN',
    '33': 'CALLER',
    '34': 'CALLVALUE',
    '35': 'CALLDATALOAD',
    '36': 'CALLDATASIZE',
    '37': 'CALLDATACOPY',
    '38': 'CODESIZE',
    '39': 'CODECOPY',
    '3a': 'GASPRICE',
    '3b': 'EXTCODESIZE',
    '3c': 'EXTCODECOPY',
    '3d': 'RETURNDATASIZE',
    '3e': 'RETURNDATACOPY',
    '3f': 'EXTCODEHASH',

    '40': 'BLOCKHASH',
    '41': 'COINBASE',
    '42': 'TIMESTAMP',
    '43': 'NUMBER',
    '44': 'DIFFICULTY',
    '45': 'GASLIMIT',
    '46': 'CHAINID',
    '47': 'SELFBALANCE',
    '48': 'BASEFEE',
    '49': '',
    '4a': '',
    '4b': '',
    '4c': '',
    '4d': '',
    '4e': '',
    '4f': '',

    '50': 'POP',
    '51': 'MLOAD',
    '52': 'MSTORE',
    '53': 'MSTORE8',
    '54': 'SLOAD',
    '55': 'SSTORE',
    '56': 'JUMP',
    '57': 'JUMPI',
    '58': 'PC',
    '59': 'MSIZE',
    '5a': 'GAS',
    '5b': 'JUMPDEST',
    '5c': '',
    '5d': '',
    '5e': '',
    '5f': '',

    '60': 'PUSH1',
    '61': 'PUSH2',
    '62': 'PUSH3',
    '63': 'PUSH4',
    '64': 'PUSH5',
    '65': 'PUSH6',
    '66': 'PUSH7',
    '67': 'PUSH8',
    '68': 'PUSH9',
    '69': 'PUSH10',
    '6a': 'PUSH11',
    '6b': 'PUSH12',
    '6c': 'PUSH13',
    '6d': 'PUSH14',
    '6e': 'PUSH15',
    '6f': 'PUSH16',

    '70': 'PUSH17',
    '71': 'PUSH18',
    '72': 'PUSH19',
    '73': 'PUSH20',
    '74': 'PUSH21',
    '75': 'PUSH22',
    '76': 'PUSH23',
    '77': 'PUSH24',
    '78': 'PUSH25',
    '79': 'PUSH26',
    '7a': 'PUSH27',
    '7b': 'PUSH28',
    '7c': 'PUSH29',
    '7d': 'PUSH30',
    '7e': 'PUSH31',
    '7f': 'PUSH32',

    '80': 'DUP1',
    '81': 'DUP2',
    '82': 'DUP3',
    '83': 'DUP4',
    '84': 'DUP5',
    '85': 'DUP6',
    '86': 'DUP7',
    '87': 'DUP8',
    '88': 'DUP9',
    '89': 'DUP10',
    '8a': 'DUP11',
    '8b': 'DUP12',
    '8c': 'DUP13',
    '8d': 'DUP14',
    '8e': 'DUP15',
    '8f': 'DUP16',

    '90': 'SWAP1',
    '91': 'SWAP2',
    '92': 'SWAP3',
    '93': 'SWAP4',
    '94': 'SWAP5',
    '95': 'SWAP6',
    '96': 'SWAP7',
    '97': 'SWAP8',
    '98': 'SWAP9',
    '99': 'SWAP10',
    '9a': 'SWAP11',
    '9b': 'SWAP12',
    '9c': 'SWAP13',
    '9d': 'SWAP14',
    '9e': 'SWAP15',
    '9f': 'SWAP16',

    'a0': 'LOG0',
    'a1': 'LOG1',
    'a2': 'LOG2',
    'a3': 'LOG3',
    'a4': 'LOG4',
    'a5': '',
    'a6': '',
    'a7': '',
    'a8': '',
    'a9': '',
    'aa': '',
    'ab': '',
    'ac': '',
    'ad': '',
    'ae': '',
    'af': '',

    'b0': 'PUSH',
    'b1': 'DUP',
    'b2': 'SWAP',
    'b3': '',
    'b4': '',
    'b5': '',
    'b6': '',
    'b7': '',
    'b8': '',
    'b9': '',
    'ba': '',
    'bb': '',
    'bc': '',
    'bd': '',
    'be': '',
    'bf': '',

    'c0': '',
    'c1': '',
    'c2': '',
    'c3': '',
    'c4': '',
    'c5': '',
    'c6': '',
    'c7': '',
    'c8': '',
    'c9': '',
    'ca': '',
    'cb': '',
    'cc': '',
    'cd': '',
    'ce': '',
    'cf': '',

    'd0': '',
    'd1': '',
    'd2': '',
    'd3': '',
    'd4': '',
    'd5': '',
    'd6': '',
    'd7': '',
    'd8': '',
    'd9': '',
    'da': '',
    'db': '',
    'dc': '',
    'dd': '',
    'de': '',
    'df': '',

    'e0': '',
    'e1': '',
    'e2': '',
    'e3': '',
    'e4': '',
    'e5': '',
    'e6': '',
    'e7': '',
    'e8': '',
    'e9': '',
    'ea': '',
    'eb': '',
    'ec': '',
    'ed': '',
    'ee': '',
    'ef': '',

    'f0': 'CREATE',
    'f1': 'CALL',
    'f2': 'CALLCODE',
    'f3': 'RETURN',
    'f4': 'DELEGATECALL',
    'f5': 'CREATE2',
    'f6': '',
    'f7': '',
    'f8': '',
    'f9': '',
    'fa': 'STATICCALL',
    'fb': '',
    'fc': '',
    'fd': 'REVERT',
    'fe': '',
    'ff': 'SELFDESTRUCT',
}

def hex_to_dec(x):
    return int(x, 16)

def clean_hex(d):
    return hex(d).rstrip('L')

def validate_block(block):
    if isinstance(block, basestring):
        if block not in BLOCK_TAGS:
            raise ValueError('invalid block tag')
    if isinstance(block, int):
        block = hex(block)
    return block

def wei_to_ether(wei):
    return 1.0 * wei / 10**18

def szabo_to_wei(szabo):
    return szabo * 10**12

def finney_to_wei(finney):
    return finney * 10**15

def ether_to_wei(ether):
    return ether * 10**18

def get_pc_op_set(code: str) -> set:
    pc_op_set = set()
    code = code.lower()[2:]
    i = 0
    while i < len(code):
        # print('{}_{}'.format(i // 2, EVM_OPCODE[code[i:i+2]]))
        pc_op_set.add('{}_{}'.format(i // 2, EVM_OPCODE[code[i:i+2]]))
        if int('60', 16) <= int(code[i:i+2], 16) and int(code[i:i+2], 16) <= int('7f', 16):
            i += (int(code[i:i+2], 16) - int('60', 16) + 1) * 2
        i += 2
    return pc_op_set


def get_opcode_number(code: str):
    code = code.lower()[2:]
    i = 0
    num = 0
    while i < len(code):
        # print('{}_{}'.format(i // 2, EVM_OPCODE[code[i:i+2]]))
        num += 1
        if int('60', 16) <= int(code[i:i+2], 16) and int(code[i:i+2], 16) <= int('7f', 16):
            i += (int(code[i:i+2], 16) - int('60', 16) + 1) * 2
        i += 2
    
    return num

if __name__ == '__main__':
    code = "0x608060405234801561001057600080fd5b506004361061003a5760003560e01c8063d4b839921461015a578063f8a8fd6d146101785761003b565b5b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660005a906000604051602401610088919061075b565b6040516020818303038152906040527f2e1a7d4d000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505060405161011291906107f0565b600060405180830381858888f193505050503d8060008114610150576040519150601f19603f3d011682016040523d82523d6000602084013e610155565b606091505b505050005b610162610182565b60405161016f9190610848565b60405180910390f35b6101806101a6565b005b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660005a9060006040516024016101f3919061075b565b6040516020818303038152906040527f2e1a7d4d000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505060405161027d91906107f0565b600060405180830381858888f193505050503d80600081146102bb576040519150601f19603f3d011682016040523d82523d6000602084013e6102c0565b606091505b50505060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660005a906040516024016040516020818303038152906040527fa50ec326000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505060405161038e91906107f0565b600060405180830381858888f193505050503d80600081146103cc576040519150601f19603f3d011682016040523d82523d6000602084013e6103d1565b606091505b50505060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660005a906040516024016040516020818303038152906040527fa50ec326000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505060405161049f91906107f0565b600060405180830381858888f193505050503d80600081146104dd576040519150601f19603f3d011682016040523d82523d6000602084013e6104e2565b606091505b50505060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660005a906040516024016040516020818303038152906040527fa50ec326000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050506040516105b091906107f0565b600060405180830381858888f193505050503d80600081146105ee576040519150601f19603f3d011682016040523d82523d6000602084013e6105f3565b606091505b50505060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660005a906040516024016040516020818303038152906040527fa50ec326000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050506040516106c191906107f0565b600060405180830381858888f193505050503d80600081146106ff576040519150601f19603f3d011682016040523d82523d6000602084013e610704565b606091505b505050565b6000819050919050565b600060ff82169050919050565b6000819050919050565b600061074561074061073b84610709565b610720565b610713565b9050919050565b6107558161072a565b82525050565b6000602082019050610770600083018461074c565b92915050565b600081519050919050565b600081905092915050565b60005b838110156107aa57808201518184015260208101905061078f565b838111156107b9576000848401525b50505050565b60006107ca82610776565b6107d48185610781565b93506107e481856020860161078c565b80840191505092915050565b60006107fc82846107bf565b915081905092915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061083282610807565b9050919050565b61084281610827565b82525050565b600060208201905061085d6000830184610839565b9291505056fea2646970667358221220c4525b713d6fbecb08ef677cc7bd2765e100802944c61d25c89cbf8768ee3fcf64736f6c634300080a0033"
    get_opcode_number(code)