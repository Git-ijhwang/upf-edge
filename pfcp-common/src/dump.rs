use tracing::debug;

pub fn print_hex(buffer: &[u8], length: usize) {
    let length = length.min(buffer.len());

    debug!("Message DUMP ({} Bytes)",length);
    debug!("===================================");

    for i in (0..length).step_by(16) {
        if i+16 <= length {

            debug!("{:04x}: {:02x}{:02x} {:02x}{:02x} | {:02x}{:02x} {:02x}{:02x} | {:02x}{:02x} {:02x}{:02x} | {:02x}{:02x} {:02x}{:02x} "
                ,i
                ,buffer[i+ 0],buffer[i+ 1],buffer[i+ 2],buffer[i+ 3]
                ,buffer[i+ 4],buffer[i+ 5],buffer[i+ 6],buffer[i+ 7]
                ,buffer[i+ 8],buffer[i+ 9],buffer[i+10],buffer[i+11]
                ,buffer[i+12],buffer[i+13],buffer[i+14],buffer[i+15]);

        } else {
            let mut buf = String::new();
            let mut p;
            let _j = i;
            let mut k = 0;

            for j in i..length {
                p = format!("{:02x}", buffer[j]);

                if k==0 {
                    buf.push_str(&format!("{:04x}: ",j));
                    buf.push_str(&p);
                } else if k % 2 == 1 {
                    buf.push_str(&p);
                } else if k % 4 == 2 {
                    buf.push_str(&format!(" "));
                    buf.push_str(&p);
                } else if k % 4 == 0 {
                    buf.push_str(&format!(" | "));
                    buf.push_str(&p);
                }

                k+=1;
            }

            debug!("{}", buf);
        }
    }

    debug!(""); // 마지막 줄 바꿈
}

