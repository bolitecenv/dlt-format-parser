let hex_str = new_data.into_iter()
            .map(|b| format!("0x{:02X}", b))
            .collect::<Vec<_>>()
            .join(", ");
        println!("Current buffer (hex): {}", hex_str);