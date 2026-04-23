export function optionalProp<Key extends string, Value>(
  key: Key,
  value: Value | undefined,
): { readonly [Property in Key]?: Value } {
  if (value === undefined) {
    return {}
  }

  return { [key]: value } as { readonly [Property in Key]?: Value }
}
