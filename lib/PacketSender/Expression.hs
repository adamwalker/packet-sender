module PacketSender.Expression where

import Data.Void
import Data.Word
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Char
import Data.Digits

import Text.Megaparsec hiding (option)
import Text.Megaparsec.Char
import qualified Text.Megaparsec.Char.Lexer as L

------------------------------------------------------------------------------
--Expresssion parser
------------------------------------------------------------------------------

space' = L.space space1 (L.skipLineComment "//") (L.skipBlockComment "/*" "*/")

lexeme = L.lexeme space'

symbol = L.symbol space'

symbol' = L.symbol' space'

parens = between (symbol "(") (symbol ")")

quotes = between (symbol "\"") (symbol "\"")

squotes = between (symbol "'") (symbol "'")

decimal, octal, hexadecimal :: Integral a => Parsec Void String a
decimal     = lexeme L.decimal
octal       = lexeme L.octal
hexadecimal = lexeme L.hexadecimal

colon = symbol ":"

dot = symbol "."

hexPair :: Parsec Void String Word8
hexPair = do
    c1 <- hexDigitChar
    c2 <- hexDigitChar
    return $ fromIntegral (digitToInt c1) * 16 + fromIntegral (digitToInt c2)

base :: Parsec Void String Integer
base 
    =   symbol' "h" *> hexadecimal
    <|> symbol' "d" *> decimal
    <|> symbol' "o" *> octal

literal :: Parsec Void String [Word8]
literal = do
    width <- try $ do
        width <- decimal
        symbol "#"
        return width
    base <- base
    return $ reverse $ take width $ reverse (map fromIntegral $ digits 256 base) ++ repeat 0

expression 
    =   literal
    <|> concat <$> (replicate <$> (try (decimal <* symbol "*")) <*> expressions)
    <|> quotes (many (fromIntegral . fromEnum <$> (anySingleBut '"')))
    <|> squotes (many (fromIntegral . fromEnum <$> (anySingleBut '\'')))
    <|> lexeme (pure <$> hexPair)
    <|> parens expressions

expressions = concat <$> some expression

topParser :: Parsec Void String ByteString
topParser = do
    res <- expressions
    eof
    return $ BS.pack res

