//extern crate serde;
use crate::Deck;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[test]
fn tests_deck() {
    let test_file = "./kats/test_vector_bytes.txt";
    let file = File::open(test_file).unwrap();
    let mut reader = BufReader::new(file).lines();

    while let Some(line) = reader.next() {
        // key to be used for instantiating deck function
        let key = line.unwrap();
        let key = key.split(" ").collect::<Vec<_>>()[4];
        let key = hex::decode(key).unwrap();

        // nonce to be used for instantiating deck function
        let nonce = reader.next().unwrap().unwrap();
        let nonce = nonce.split(" ").collect::<Vec<_>>()[4];
        let nonce = hex::decode(nonce).unwrap();

        // message to be absorbed into deck function
        let msg = reader.next().unwrap().unwrap();
        let msg = msg.split(" ").collect::<Vec<_>>()[4];
        let mut buf = hex::decode(msg).unwrap();
        let msg = buf.clone();

        // # expected cipher text to be compared to
        let exp_cipher = reader.next().unwrap().unwrap();
        let exp_cipher = exp_cipher.split(" ").collect::<Vec<_>>()[4];
        let exp_cipher = hex::decode(exp_cipher).unwrap();

        // # expected tag to be compared to
        let exp_tag = reader.next().unwrap().unwrap();
        let exp_tag = exp_tag.split(" ").collect::<Vec<_>>()[4];
        let exp_tag = hex::decode(exp_tag).unwrap();

        let mut deck = Deck::new(&key, &nonce);
        deck.wrap(&mut buf).unwrap();

        let ct = &buf[..&buf.len()-36];
        let tag = &buf[buf.len()-32..];

        if ct.len() > 36 {
            assert_eq!(&exp_cipher, ct);
        }
        assert_eq!(&tag, &exp_tag);
        
        let mut deck = Deck::new(&key, &nonce);
        deck.unwrap(&mut buf).unwrap();
        if buf.len() > 0 {
            assert_eq!(&msg, &buf);
        }

        let mut deck = Deck::new(&key, &nonce);
        deck.wrap_last(&mut buf).unwrap();

        let ct = &buf[..&buf.len()-36];
        let tag = &buf[buf.len()-32..];

        if ct.len() > 36 {
            assert_eq!(&exp_cipher, ct);
        }
        assert_eq!(&tag, &exp_tag);
        
        let mut deck = Deck::new(&key, &nonce);
        deck.unwrap_last(&mut buf).unwrap();
        if buf.len() > 0 {
            assert_eq!(&msg, &buf);
        }
    }
}
