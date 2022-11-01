from typing import List, Dict, Tuple
import random

from scheduler import Variable

class Linker:
    def __init__(self):
        self.label_index: int = 0
        pass

    def _generate_variable_label(self) -> str:
        self.label_index += 1
        return '$PARAMETER_' + str(self.label_index) + '$'

    def linking(self, 
                testc_address: str,
                testc_abi: List[Dict], 
                source_code: str) -> Tuple[List[Variable], str]:
        updated_source_code: str = source_code

        # Replace $TARGET-ADDRESS$ in the soruce_code according to the test contract's address.
        updated_source_code = updated_source_code.replace('$TARGET-ADDRESS$', testc_address, 1)

        # Replace FUNCTION-SIGNATURE-AND-PARAMETERS-LIST in the source_code according to test contract's abi.
        # Randomly choose function name from abi, but the following conditions must be met:
        #     1. function's name exists.
        #     2. stateMutability is 'nonpayable' or 'payable'.
        #     3. type is 'function'
        # Parameters type is filled accroding to abi inputs field
        # Also create variable for 'PARAMETER-LIST' after 'FUNCTION-SIGNATURE'
        variable_pool: List[Variable] = []
        function_abis = [function_abi for function_abi in testc_abi 
                         if 'name' in function_abi and function_abi['type'] == 'function' and
                         (function_abi['stateMutability'] == 'nonpayable' or function_abi['stateMutability' ] == 'payable')]

        while updated_source_code.find('$VALUE_GAS_AND_FUNCTION-SIGNATURE-AND-PARAMETERS-LIST$') != -1:
            function_signature_and_parameter_list = ''

            choose_function_index = random.randint(0, len(function_abis) - 1)
            function_name = function_abis[choose_function_index]['name']
            
            parameter_type = ''
            for input_dict_index in range(len(function_abis[choose_function_index]['inputs'])):
                parameter_type += function_abis[choose_function_index]['inputs'][input_dict_index]['type']
                if input_dict_index != len(function_abis[choose_function_index]['inputs']) - 1:
                    parameter_type += ','

            parameter_list = ''
            for input_dict_index in range(len(function_abis[choose_function_index]['inputs'])):
                variable: Variable = Variable(self._generate_variable_label(), function_abis[choose_function_index]['inputs'][input_dict_index]['type'])
                parameter_list += ', '+ variable.label
                variable_pool.append(variable)

            function_signature_and_parameter_list = '"' + function_name + '(' + parameter_type + ')"' + parameter_list

            # if function is nonpayable, value = 0, else, value is variable for fuzzing
            if function_abis[choose_function_index]['stateMutability'] == 'nonpayable':
                value_str = '0'
            else:
                variable: Variable = Variable(self._generate_variable_label(), 'uint256')
                variable_pool.append(variable)
                value_str = variable.label

            # estimating gas required, ignore in current state. In the future, you can consider implementing
            gas_str = 'gasleft()'
            value_gas_and_function_signature_and_parameter_list = '{value: ' + value_str + ', gas:' + gas_str + '}(abi.encodeWithSignature(' + function_signature_and_parameter_list + '))'
            # value_gas_and_function_signature_and_parameter_list = '{value: ' + value_str + '}(abi.encodeWithSignature(' + function_signature_and_parameter_list + '))'

            updated_source_code = updated_source_code.replace('$VALUE_GAS_AND_FUNCTION-SIGNATURE-AND-PARAMETERS-LIST$', value_gas_and_function_signature_and_parameter_list, 1)

        # return seed pool for fuzzer to mutate and updated source code
        return (variable_pool, updated_source_code)