include("MD5/MD5.jl")

function md5_collision_differentials(
  m0::Vector{UInt32},
  m1::Vector{UInt32}
)::Tuple{Vector{UInt32}, Vector{UInt32}}
  _m0 = copy(m0)
  _m1 = copy(m1)
  @inbounds _m0[5]  = UInt32(mod(m0[5]  + 1 << 31, 1 << 32))
  @inbounds _m0[12] = UInt32(mod(m0[12] + 1 << 15, 1 << 32))
  @inbounds _m0[15] = UInt32(mod(m0[15] + 1 << 31, 1 << 32))
  @inbounds _m1[5]  = UInt32(mod(m1[5]  + 1 << 31, 1 << 32))
  @inbounds _m1[12] = UInt32(mod(m1[12] - 1 << 15, 1 << 32))
  @inbounds _m1[15] = UInt32(mod(m1[15] - 1 << 31, 1 << 32))
  return _m0, _m1
end

function md5_check_collision(
  m0::Vector{UInt32},
  m1::Vector{UInt32},
  _m0::Vector{UInt32},
  _m1::Vector{UInt32}
)::Bool
  @debug "M0:  $m0"; @debug "M0': $_m0"
  @debug "M1:  $m1"; @debug "M1': $_m1"
  m0_bytes::Vector{UInt8} = collect(reinterpret(UInt8, m0))
  m1_bytes::Vector{UInt8} = collect(reinterpret(UInt8, m1))
  m0_m1_bytes::Vector{UInt8} = append!(m0_bytes, m1_bytes)
  @debug m0_m1_bytes
  _m0_bytes::Vector{UInt8} = collect(reinterpret(UInt8, _m0))
  _m1_bytes::Vector{UInt8} = collect(reinterpret(UInt8, _m1))
  _m0_m1_bytes::Vector{UInt8} = append!(_m0_bytes, _m1_bytes)
  @debug _m0_m1_bytes

  m0_m1_digest::Vector{UInt32} = ntoh.(reinterpret(UInt32, MD5.md5(m0_m1_bytes)))
  _m0_m1_digest::Vector{UInt32} = ntoh.(reinterpret(UInt32, MD5.md5(_m0_m1_bytes)))

  println("M0||M1 digest (padded, big endian):   $m0_m1_digest")
  println("M0'||M1' digest (padded, big endian): $_m0_m1_digest")
  return m0_m1_digest == _m0_m1_digest
end

function main()
  m0::Vector{UInt32} = [UInt32(htol(x)) for x in [
    0x02dd31d1, 0xc4eee6c5, 0x69a3d69,  0x5cf9af98,
    0x87b5ca2f, 0xab7e4612, 0x3e580440, 0x897ffbb8,
    0x0634ad55, 0x02b3f409, 0x8388e483, 0x5a417125,
    0xe8255108, 0x9fc9cdf7, 0xf2bd1dd9, 0x5b3c3780
  ]]

  m1_1::Vector{UInt32} = [UInt32(htol(x)) for x in [
    0xd11d0b96, 0x9c7b41dc, 0xf497d8e4, 0xd555655a,
    0xc79a7335, 0x0cfdebf0, 0x66f12930, 0x8fb109d1,
    0x797f2775, 0xeb5cd530, 0xbaade822, 0x5c15cc79,
    0xddcb74ed, 0x6dd3c55f, 0xd80a9bb1, 0xe3a7cc35
  ]]

  _m0, _m1_1 = md5_collision_differentials(m0, m1_1)

  if md5_check_collision(m0, m1_1, _m0, _m1_1)
    println("Collision for m0={$m0} and m1={$m1_1}!")
  else
    println("No collision for m0={$m0} and m1={$m1_1}!")
  end

  println()

  m1_2 = [UInt32(htol(x)) for x in [
    0x313e82d8, 0x5b8f3456, 0xd4ac6dae, 0xc619c936, 
    0xb4e253dd, 0xfd03da87, 0x06633902, 0xa0cd48d2,
    0x42339fe9, 0xe87e570f, 0x70b654ce, 0x1e0da880, 
    0xbc2198c6, 0x9383a8b6, 0x2b65f996, 0x702af76f
  ]]

  _m0, _m1_2 = md5_collision_differentials(m0, m1_2)

  if md5_check_collision(m0, m1_2, _m0, _m1_2)
    println("Collision for m0={$m0} and m1={$m1_2}!")
  else
    println("No collision for m0={$m0} and m1={$m1_2}!")
  end
end

if abspath(PROGRAM_FILE) == @__FILE__
  main()
end
