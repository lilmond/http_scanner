import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to C99 CSV output.")
    parser.add_argument("-s", "--save", type=str, required=True, choices=["domain", "host_ip"], help="Choose which data to extract.")

    args = parser.parse_args()

    try:
        with open(args.file, "r") as file:
            lines = file.read().splitlines()
            file.close()
    except FileNotFoundError:
        print(f"Error: This file does not exist.")
        return
    
    file_extension, file_name = args.file[::-1].split(".", 1)
    file_name = file_name[::-1]
    file_extension = file_extension[::-1]

    output_filename = f"{file_name} {args.save}"
    output_file = f"{output_filename}.txt"

    for line in lines:
        if line == "Subdomain,IP,Cloudflare":
            continue

        line = line.strip()
        domain, host_ip, cloudflare_protected = line.split(",")
        
        with open(output_file, "a") as file:
            file.write(f"{locals()[args.save]}\n")
            file.close()

    print(f"Output file: {output_file}")

if __name__ == "__main__":
    main()
