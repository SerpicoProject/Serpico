class JPEG
  attr_reader :width, :height
  def initialize(file)
    if file.kind_of? IO
      examine(file)
    else
      File.open(file, 'rb') { |io| examine(io) }
    end
  end
private
  def examine(io)
    class << io
      def getc; super.bytes.first; end
      def readchar; super.bytes.first; end
      def readint; (readchar << 8) + readchar; end
      def readframe; read(readint - 2); end
      def readsof; [readint, readchar, readint, readint, readchar]; end
      def next
        c = readchar while c != 0xFF
        c = readchar while c == 0xFF
        c
      end
    end
    raise 'malformed JPEG' unless io.getc == 0xFF && io.getc == 0xD8 # SOI
    while marker = io.next
      case marker
        when 0xC0..0xC3, 0xC5..0xC7, 0xC9..0xCB, 0xCD..0xCF # SOF markers
          length, @bits, @height, @width, components = io.readsof
          raise 'malformed JPEG' unless length == 8 + components * 3
        when 0xD9, 0xDA then  break # EOI, SOS
        when 0xFE then        @comment = io.readframe # COM
        when 0xE1 then        io.readframe # APP1, contains EXIF tag
        else                  io.readframe # ignore frame
      end
    end
  end
end

def jpeg?(data)
  return data[0,4]=="\xff\xd8\xff\xe0".force_encoding(Encoding::ASCII_8BIT)
end

def png?(data)
  return data[0,8]=="\x89\x50\x4e\x47\x0d\x0a\x1a\x0a".force_encoding(Encoding::ASCII_8BIT)
end

