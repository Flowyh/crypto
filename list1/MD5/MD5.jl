module MD5


using SHA: lrot, SHA_CTX
import SHA: update!, digest!, transform!, pad_remainder!, buffer_pointer
import SHA: blocklen, state_type, digestlen, short_blocklen
export md5
export md5_unpadded

# Note: this code more or less comes directly from https://en.wikipedia.org/wiki/MD5
# I believe this is fair use. and does not have license implications

const kk =  floor.(UInt32, Int64(2)^32 * abs.(sin.(1:64)))

const ss = UInt64[
7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
]

const MD5_initial_hash_value = UInt32[0x67452301, 0xefcdab89, 0x98badcfe,  0x10325476] # A,B,C,D

mutable struct MD5_CTX <: SHA_CTX
    state::Array{UInt32,1}
    bytecount::UInt64
    buffer::Array{UInt8,1}
    used::Bool
end

digestlen(::Type{MD5_CTX}) = 16
state_type(::Type{MD5_CTX}) = UInt32
# blocklen is the number of bytes of data processed by the transform!() function at once
blocklen(::Type{MD5_CTX}) = UInt64(64)

MD5_CTX() = MD5_CTX(copy(MD5_initial_hash_value), 0, zeros(UInt8, blocklen(MD5_CTX)), false)
Base.show(io::IO, ::MD5_CTX) = write(io, "MD5 hash state")

let body = quote end
    ex  = quote
        pbuf = buffer_pointer(context)
        @inbounds A = context.state[1]
        @inbounds B = context.state[2]
        @inbounds C = context.state[3]
        @inbounds D = context.state[4]
    end
    push!(body.args, ex)
    for i in 0:63
        if 0 ≤ i ≤ 15
            ex = :(F = (B & C) | ((~B) & D))
            g = i
        elseif 16 ≤ i ≤ 31
            ex = :(F = (D & B) | ((~D) & C))
            g = 5i + 1
        elseif 32 ≤ i ≤ 47
            ex = :(F = B ⊻ C ⊻ D)
            g = 3i + 5
        elseif 48 ≤ i ≤ 63
            ex = :(F = C ⊻ (B | (~D)))
            g = 7i
        end
        push!(body.args, ex)
        g = (g % 16) + 1
        ex = quote
            temp = D
            D = C
            C = B
            inner = A + F + $(kk[i+1]) + unsafe_load(pbuf, $g)
            rot_inner = lrot($(ss[i+1]), inner, 32)
            B = B + rot_inner
            A = temp
        end
        push!(body.args, ex)
    end

    ex = quote
        @inbounds context.state[1] += A
        @inbounds context.state[2] += B
        @inbounds context.state[3] += C
        @inbounds context.state[4] += D
    end
    push!(body.args, ex)

    @eval function transform!(context::MD5_CTX)
        $body
    end
end

function digest!(context::T) where {T<:MD5_CTX}
    pad_remainder!(context)

    bitcount_idx = div(short_blocklen(T), sizeof(context.bytecount)) + 1
    pbuf = Ptr{typeof(context.bytecount)}(pointer(context.buffer))
    unsafe_store!(pbuf, 8context.bytecount, bitcount_idx)

    # Final transform:
    transform!(context)

    # ctx has been mutated
    reinterpret(UInt8, context.state)
end

function digest_unpadded!(context::T) where {T<:MD5_CTX} # Scary!
    bitcount_idx = div(short_blocklen(T), sizeof(context.bytecount)) + 1
    pbuf = Ptr{typeof(context.bytecount)}(pointer(context.buffer))
    unsafe_store!(pbuf, 8context.bytecount, bitcount_idx)

    # Final transform:
    transform!(context)

    # ctx has been mutated
    reinterpret(UInt8, context.state)
end

# Our basic function is to process arrays of bytes
function md5(data::T) where T<:Union{AbstractVector{UInt8}, NTuple{N,UInt8} where N}
    ctx = MD5_CTX()
    update!(ctx, data)
    return digest!(ctx)
end

# Our basic function is to process arrays of bytes
function md5_unpadded(data::T) where T<:Union{AbstractVector{UInt8}, NTuple{N,UInt8} where N} # Scary!
    ctx = MD5_CTX()
    update!(ctx, data)
    return digest_unpadded!(ctx)
end

# AbstractStrings are a pretty handy thing to be able to crunch through
md5(str::AbstractString) = md5(codeunits(str))

# Convenience function for IO devices, allows for things like:
# open("test.txt") do f
#     sha256(f)
# done
function md5(io::IO, chunk_size=4*1024)
    ctx = MD5_CTX()
    buff = Vector{UInt8}(undef, chunk_size)
    while !eof(io)
        num_read = readbytes!(io, buff)
        update!(ctx, buff[1:num_read])
    end
    return digest!(ctx)
end

end # module