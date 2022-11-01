from type import Grammar

SOLIDITY_GRAMMAR: Grammar = {
    '<start>': [
        '<source-unit>'
    ],
    '<source-unit>': [
        'pragma solidity 0.8.10; <contract-definition>'
    ],
    '<contract-definition>': [
        'contract TestContract { <state-variable-definition> <constructor-definition> <function-definition> <fallback-function-definition> }'
    ],
    '<state-variable-definition>': [
        'address public target;'
    ],
    '<constructor-definition>': [
        'constructor () <constructor-block>',
        'constructor () payable <constructor-block>',
        'constructor () public <constructor-block>'
    ],
    '<constructor-block>': [
        '{ target = $TARGET-ADDRESS$; }'
    ],
    '<function-definition>': [
        'function test () public <state-mutability> <block>',
        'function test () public <block>'
    ],
    '<fallback-function-definition>': [
        'fallback () external <state-mutability> <block>',
        'fallback () external <block>'
    ],
    '<state-mutability>': [
        # 'pure',
        # 'view',
        'payable',
    ],
    '<block>': [
        '{ <statements> }'
    ],
    '<statements>': [
        '<statement>',
        '<statement> <statements>'
    ],
    '<statement>': [
        '<block>',
        '<expression-statement>'
    ],

    '<expression-statement>': [
        '<expression>;'
    ],
    '<expression>': [
        'target.call$VALUE_GAS_AND_FUNCTION-SIGNATURE-AND-PARAMETERS-LIST$'
    ]
}