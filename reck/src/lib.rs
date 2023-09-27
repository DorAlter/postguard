use xoofff::Xoofff;

#[cfg(test)]
mod tests;

/// The length of the authentication tags (in bytes).
const TAG_LEN: usize = 32;

/// Length of the domain seperation (in bits).
const DS_BIT_LEN: usize = 1;

/// The length of the counter (in bytes).
const COUNTER_LEN: usize = 4;

/// The length of the counter plus the authentication tags (in bytes).
const COUNTER_TAG_LEN: usize = TAG_LEN + COUNTER_LEN;

pub struct Deck {
    xoofff: Xoofff,
    counter: u32,
}

#[derive(Debug)]
pub enum Error {
    Overflow,
    WrongTag,
}

impl Deck {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        let mut xoofff = Xoofff::new(key);

        xoofff.absorb(nonce);
        xoofff.finalize(0, 0, 0);
        xoofff.restart();

        Deck { xoofff, counter: 0 }
    }

    #[inline(always)]
    fn _absorb_finalize_squeeze(&mut self, deck: &mut Xoofff, msg: &[u8], domain_seperator: u8, out : &mut [u8] ){
        deck.absorb(msg);
        deck.finalize(domain_seperator, DS_BIT_LEN, 0);
        deck.squeeze(out);
        deck.restart();
    }

    #[inline(always)]
    fn _absorb_finalize(&mut self, deck: &mut Xoofff, msg: &[u8], domain_seperator: u8 ){
        deck.absorb(msg);
        deck.finalize(domain_seperator, DS_BIT_LEN, 0);
    }

    #[inline(always)]
    fn _xor(&self, buf_out: &mut [u8], buf_in: Vec<u8> ){
        for (plain, s) in buf_out.iter_mut().zip(buf_in.iter()) {
            *plain ^= s;
        }
    }

    #[inline(always)]
    fn _wrap(&mut self, plain: &mut Vec<u8>) -> Result<(), Error> {
        let mut cloned = self.xoofff.clone();
        let mut tag = [0u8; TAG_LEN];

        if plain.len() > 0 {
            let mut squeezed = vec![0u8; plain.len()];
            self._absorb_finalize_squeeze(&mut cloned, &self.counter.to_be_bytes(), 0b0, &mut squeezed);
            self._xor(plain, squeezed);
            self._absorb_finalize_squeeze(&mut cloned, &plain.as_slice(), 0b1, &mut tag);

        } else {
            self._absorb_finalize_squeeze(&mut cloned, &self.counter.to_be_bytes(), 0b1, &mut tag);
        };

        plain.extend_from_slice(&self.counter.to_be_bytes());
        plain.extend_from_slice(&tag);

        self.counter = self.counter.checked_add(1).ok_or(Error::Overflow)?;

        Ok(())
    }

    #[inline(always)]
    pub fn wrap(&mut self, plain: &mut Vec<u8>) -> Result<(), Error> {
        self._wrap(plain)
    }

    #[inline(never)]
    pub fn wrap_last(mut self, plain: &mut Vec<u8>) -> Result<(), Error> {
        self._wrap(plain)
    }

    #[inline(always)]
    fn _unwrap(&mut self, cipher: &mut Vec<u8>) -> Result<(), Error> {
        let mut cloned = self.xoofff.clone();
        let mut cloned2: Option<Xoofff> = None;
        let tag;

        if cipher.len() > COUNTER_TAG_LEN {
            let ct = &cipher[..cipher.len()-COUNTER_TAG_LEN];
            tag = &cipher[cipher.len()-TAG_LEN..];
            let counter = &cipher[cipher.len()-COUNTER_TAG_LEN..cipher.len()-TAG_LEN];
            self._absorb_finalize(&mut cloned, &counter, 0b0);
            cloned2 = Some(cloned.clone());

            cloned.restart();
            self._absorb_finalize(&mut cloned, &ct, 0b1);
        } else {
            tag = &cipher[COUNTER_LEN..];
            let counter = &cipher[..COUNTER_LEN];
            self._absorb_finalize(&mut cloned, &counter, 0b1);
        }

        let mut tag_prime = [0u8; TAG_LEN];
        cloned.squeeze(&mut tag_prime);

        if tag != tag_prime {
            return Err(Error::WrongTag);
        }

        if cipher.len() > COUNTER_TAG_LEN {
            let mut squeezed = vec![0u8; cipher.len()-COUNTER_TAG_LEN];
            cloned2.unwrap().squeeze(&mut squeezed); // cannot panic
            self._xor(cipher, squeezed);
        }

        cipher.truncate(cipher.len()-COUNTER_TAG_LEN);
        Ok(())
    }

    #[inline(always)]
    pub fn unwrap(&mut self, ct: &mut Vec<u8>) -> Result<(), Error> {
        self._unwrap(ct)
    }

    #[inline(never)]
    pub fn unwrap_last(&mut self, ct: &mut Vec<u8>) -> Result<(), Error> {
        self._unwrap(ct)
    }
}
